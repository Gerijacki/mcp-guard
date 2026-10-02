package rules

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/Gerijacki/mcp-guard/internal/finding"
	"github.com/Gerijacki/mcp-guard/internal/source"
)

// MCPG013: a credential read from the environment (or received as a tool argument) is
// written to logs or returned to the model.
type secretLeakRule struct{}

var (
	secretNameRe = regexp.MustCompile(`(?i)(?:api[_-]?key|apikey|secret|token|passw(?:or)?d|passwd|credential|private[_-]?key|bearer|auth[_-]?header|authorization)`)
	notSecretRe  = regexp.MustCompile(`(?i)(?:^|_)(?:id|ids|url|uri|path|file|dir|host|name|count|limit|max|min|ttl|expir\w*|type|region|timeout|len|length|size|usage|used|budget|tokenizer|tokens|endpoint|prefix|suffix|mode|enabled|flag)(?:$|_)|(?:Id|Url|Uri|Path|File|Dir|Host|Name|Count|Limit|Max|Min|Ttl|Type|Region|Timeout|Length|Size|Usage|Tokens|Endpoint)$`)
	envReadRe    = regexp.MustCompile(`^\s*(?:(?:const|let|var|export)\s+)?([A-Za-z_$][\w$]*)\s*(?::\s*[\w\[\], .|"']+)?\s*(?::=|=)\s*(?:os\.environ(?:\.get)?\s*[\[(]\s*["']([^"']+)["']|os\.getenv\s*\(\s*["']([^"']+)["']|process\.env\.(\w+)|process\.env\[\s*["']([^"']+)["']\s*\]|os\.Getenv\s*\(\s*"([^"]+)")`)
	logSinks     = compileByLang(map[source.Language]string{
		source.Python:     `(?:^|[^.\w])print\s*\(|\b(?:logging|logger|log|LOGGER|_logger|_log)\.(?:debug|info|warning|warn|error|exception|critical|log)\s*\(|\bctx\.(?:info|debug|warning|error)\s*\(`,
		source.TypeScript: `\bconsole\.(?:log|info|debug|warn|error|trace)\s*\(|\b(?:logger|log)\.(?:debug|info|warn|error|log|trace)\s*\(`,
		source.Go:         `\blog\.(?:Print\w*|Fatal\w*|Panic\w*)\s*\(|\bfmt\.(?:Print\w*|Fprint\w*)\s*\(|\bslog\.(?:Debug|Info|Warn|Error)\w*\s*\(|\b(?:logger|log)\.(?:Debug|Info|Warn|Error)\w*\s*\(`,
	})
	envDumpRe = compileByLang(map[source.Language]string{
		source.Python:     `\bos\.environ\b(?:\s*[,)\n]|\s*$|\.copy\(\)|\.items\(\)|\.values\(\))|\bdict\s*\(\s*os\.environ\s*\)`,
		source.TypeScript: `\bprocess\.env\b(?:\s*[,)\n]|\s*$|\s*\))|\bObject\.(?:entries|values|assign)\s*\(\s*process\.env`,
		source.Go:         `\bos\.Environ\s*\(\s*\)`,
	})
	maskedRe = regexp.MustCompile(`(?i)mask|redact|obfuscat|\*{3,}|\[:\d+\]|\blen\s*\(|\.length\b|\bbool\s*\(|is None|is not None|(?:!=|==|!==|===)\s*(?:nil|null|undefined|""|'')|!!\s*\w|\bhash\b|sha\d*\(|\bnot\s+\w|\bif\s+\w+\s*(?:else|:)`)
)

func (secretLeakRule) Meta() Meta {
	return Meta{
		ID:       "MCPG013",
		Name:     "secret-in-logs-or-output",
		Severity: finding.Medium,
		Summary:  "Credential written to logs or returned to the model",
		Description: "A value that holds a credential (an API key or token read from the environment, or a tool " +
			"argument named like one) is printed, logged or returned from the tool, or the whole environment is " +
			"dumped. Logs are shipped to third parties and read by many people, stdout is part of the protocol " +
			"on stdio servers, and anything a tool returns enters the model's context, where a prompt " +
			"injection can ask for it and send it elsewhere.",
		Remediation: "Never log or return credentials. Log only that a key is present (`bool(api_key)`), mask all but a " +
			"few characters, and keep secrets out of tool results and error messages. Do not dump os.environ or " +
			"process.env; return an explicit allowlist of non-secret settings instead.",
		CWE:   []string{"CWE-532", "CWE-200"},
		OWASP: []string{"MCP01:2025", "LLM02:2025", "ASI03:2026"},
	}
}

func isSecretName(n string) bool { return secretNameRe.MatchString(n) && !notSecretRe.MatchString(n) }

func (r secretLeakRule) Check(f *source.File) []finding.Finding {
	logs, dump := logSinks[f.Language], envDumpRe[f.Language]
	if logs == nil {
		return nil
	}
	if !containsAny(f.Content, "environ", "getenv", "Getenv", "process.env", "Environ") && !containsAny(strings.ToLower(f.Content), "secret", "token", "password", "passwd", "api_key", "apikey", "credential", "authorization", "bearer", "private_key") {
		return nil
	}
	// Variables that hold credentials read from the environment, anywhere in the file
	// (module-level constants are the common case).
	secrets := map[string]bool{}
	for _, line := range f.Lines {
		if m := envReadRe.FindStringSubmatch(line); m != nil {
			key := strings.Join(m[2:], "")
			if isSecretName(m[1]) || isSecretName(key) {
				secrets[m[1]] = true
			}
		}
	}
	var out []finding.Finding
	for _, t := range toolBodies(f) {
		local := map[string]bool{}
		for k := range secrets {
			local[k] = true
		}
		// A credential the model itself passed in is already in its context: logging it is a
		// leak, but echoing it back in the result is not.
		argSecrets := map[string]bool{}
		for _, p := range t.Params {
			if isSecretName(p) {
				argSecrets[p] = true
			}
		}
		for _, st := range f.ToolStatements(t) {
			if a, ok := parseAssign(st.Text); ok && len(a.ids) == 1 {
				if m := envReadRe.FindStringSubmatch(st.Text); m != nil && (isSecretName(m[1]) || isSecretName(strings.Join(m[2:], ""))) {
					local[a.ids[0]] = true
				}
			}
			isLog := logs.MatchString(st.Text)
			isReturn := returnStmtRe.MatchString(st.Text)
			if (!isLog && !isReturn) || maskedRe.MatchString(st.Text) {
				continue
			}
			what := ""
			for id := range local {
				if source.ContainsIdent(st.Text, id) {
					what = fmt.Sprintf("the credential %q", id)
					break
				}
			}
			if what == "" && isLog { // only logging a model-supplied credential is a leak
				for id := range argSecrets {
					if source.ContainsIdent(st.Text, id) {
						what = fmt.Sprintf("the credential %q", id)
						break
					}
				}
			}
			if what == "" && dump != nil && dump.MatchString(st.Text) {
				what = "the whole environment (which holds credentials)"
			}
			if what == "" {
				continue
			}
			sev, where := finding.Medium, "writes "+what+" to the logs"
			if isReturn {
				sev, where = finding.High, "returns "+what+" to the model"
			}
			out = append(out, newFinding(r.Meta(), f, st.Line, sev, t.Name,
				fmt.Sprintf("%s %q %s, exposing it beyond the process.", t.Noun(), t.Name, where)))
			break
		}
	}
	return out
}
