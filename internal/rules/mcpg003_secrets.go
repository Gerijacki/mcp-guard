package rules

import (
	"fmt"
	"math"
	"path"
	"regexp"
	"sort"
	"strings"
	"unicode"

	"github.com/Gerijacki/mcp-guard/internal/finding"
	"github.com/Gerijacki/mcp-guard/internal/source"
)

// MCPG003: credentials hard-coded in MCP server code, client configs or env files.
type secretRule struct{}

type secretPattern struct {
	name string
	re   *regexp.Regexp
}

// Known credential formats. These are reported regardless of variable names.
var knownSecrets = []secretPattern{
	{"Anthropic API key", regexp.MustCompile(`\bsk-ant-(?:api|admin|oat)\d{2}-[A-Za-z0-9_\-]{20,}`)},
	{"OpenAI API key", regexp.MustCompile(`\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_\-]{20,}|\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b|\bsk-[A-Za-z0-9]{48}\b`)},
	{"GitHub token", regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{36,255}\b|\bgithub_pat_[A-Za-z0-9_]{60,255}\b`)},
	{"GitLab token", regexp.MustCompile(`\bglpat-[A-Za-z0-9_\-]{20,}\b`)},
	{"AWS access key ID", regexp.MustCompile(`\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b`)},
	{"Slack token", regexp.MustCompile(`\bxox[baprse]-[A-Za-z0-9-]{10,}\b`)},
	{"Slack webhook URL", regexp.MustCompile(`https://hooks\.slack\.com/services/T[A-Za-z0-9_]+/B[A-Za-z0-9_]+/[A-Za-z0-9_]+`)},
	{"Stripe live key", regexp.MustCompile(`\b(?:sk|rk)_live_[A-Za-z0-9]{20,}\b`)},
	{"Google API key", regexp.MustCompile(`\bAIza[0-9A-Za-z_\-]{35}\b`)},
	{"Hugging Face token", regexp.MustCompile(`\bhf_[A-Za-z0-9]{30,}\b`)},
	{"npm token", regexp.MustCompile(`\bnpm_[A-Za-z0-9]{36}\b`)},
	{"Notion token", regexp.MustCompile(`\bntn_[A-Za-z0-9]{40,}\b`)},
	{"Linear API key", regexp.MustCompile(`\blin_api_[A-Za-z0-9]{40}\b`)},
	{"SendGrid API key", regexp.MustCompile(`\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b`)},
	{"Private key", regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----`)},
}

var (
	// key = "value" / "key": "value" where the key name looks like a credential.
	genericAssignRe = regexp.MustCompile(`(?i)[\w.-]*?(?:api[_-]?key|apikey|secret|token|passw(?:or)?d|pwd|auth[_-]?token|credentials?|private[_-]?key|access[_-]?key|client[_-]?secret)(?:[_.-][\w.-]*)?["']?\s*(?::=|[:=])\s*["']([^"'\s]{8,})["']`)
	// Authorization: "Bearer <token>"
	authHeaderRe = regexp.MustCompile(`(?i)["']?authorization["']?\s*[:=,]\s*["'](?:Bearer|Basic|Token)\s+([^"'\s]{12,})["']`)
	// KEY=value lines in .env files
	envAssignRe = regexp.MustCompile(`(?i)^\s*(?:export\s+)?[A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|PWD|CREDENTIALS?)[A-Z0-9_]*\s*=\s*["']?([^"'\s#]{8,})`)
	// scheme://user:password@host
	connStringRe = regexp.MustCompile(`\b[a-zA-Z][a-zA-Z0-9+.\-]{1,20}://[^\s:@/"'$<{]+:([^\s@/"'$<{]{3,})@([^\s"'/:?#]+)`)
	// Hosts that indicate local development defaults or documentation examples.
	devHostRe = regexp.MustCompile(`^(?:localhost|127\.0\.0\.1|0\.0\.0\.0|\[?::1\]?|host\.docker\.internal|.*\.(?:example|test|local|localhost|invalid)|example\.(?:com|org|net))$`)
	// Default credentials that only appear in local/dev setups and docs.
	trivialPasswords = map[string]bool{"password": true, "pass": true, "postgres": true, "root": true, "admin": true,
		"secret": true, "user": true, "guest": true, "mysql": true, "changeme": true, "pwd": true}
	templateFileRe = regexp.MustCompile(`(?i)example|sample|template|\.dist$|\.defaults?$`)

	placeholderRe = regexp.MustCompile(`(?i)example|placeholder|your[_-]|xxx|changeme|change_me|dummy|sample|redacted|\*\*\*|<|>|\$\{|\{\{|%\(|process\.env|os\.environ|getenv|env\(|^\$|test|fake|mock|replace|insert|todo|none|null|undefined|secret_?here|key_?here|token_?here|invalid|0123456|123456789|abcdefgh|qwerty|lorem`)
	envVarNameRe  = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)
)

func (secretRule) Meta() Meta {
	return Meta{
		ID:       "MCPG003",
		Name:     "hardcoded-secret",
		Severity: finding.Critical,
		Summary:  "Credential hard-coded in MCP server code or configuration",
		Description: "An API key, token, password or private key is written in clear text in the server " +
			"source, an MCP client configuration (mcp.json, claude_desktop_config.json, .vscode/mcp.json…) " +
			"or an env file. These files are routinely committed, shared in READMEs and copied between machines. " +
			"MCP servers usually hold broad credentials (GitHub, cloud, databases), so a leak gives an " +
			"attacker the same power as the agent.",
		Remediation: "Remove the secret and rotate it (assume it is compromised). Load credentials from the " +
			"environment or a secret manager at runtime; in client configs reference variables " +
			"(e.g. \"${env:GITHUB_TOKEN}\" or the client's input/secret prompt) instead of literal values.",
		CWE:   []string{"CWE-798", "CWE-312"},
		OWASP: []string{"MCP01:2025", "LLM02:2025", "ASI03:2026"},
	}
}

func (r secretRule) Check(f *source.File) []finding.Finding {
	var out []finding.Finding
	seen := map[int]bool{}
	// add reports the secret found at byte range [start, end) of line n (start < 0: unknown).
	add := func(n int, sev finding.Severity, kind string, start, end int) {
		if seen[n] {
			return
		}
		seen[n] = true
		line := f.Line(n)
		if start >= 0 && end <= len(line) {
			line = line[:start] + redact(line[start:end]) + line[end:]
		}
		fd := newFinding(r.Meta(), f, n, sev, "", fmt.Sprintf("%s found in %s.", kind, describeFile(f)))
		fd.Snippet = snippet(line)
		out = append(out, fd)
	}
	addValue := func(n int, sev finding.Severity, kind, secret string) {
		i := strings.Index(f.Line(n), secret)
		if i < 0 {
			add(n, sev, kind, -1, -1)
			return
		}
		add(n, sev, kind, i, i+len(secret))
	}

	// Any high-entropy literal in the env/headers of an MCP client config is a secret,
	// whatever its variable is called (e.g. "DATABASE_URL", "X-Custom").
	for _, s := range f.Servers {
		for _, kv := range []map[string]string{s.Env, s.Headers} {
			keys := make([]string, 0, len(kv))
			for k := range kv {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				v := kv[k]
				if strings.HasPrefix(strings.ToLower(v), "bearer ") {
					v = strings.TrimSpace(v[len("bearer "):])
				}
				if len(v) >= 16 && looksLikeSecret(v, 3.5) && !strings.Contains(v, "/") {
					addValue(f.FindLine(`"`+k+`"`, s.Line), finding.Critical,
						fmt.Sprintf("Literal credential in %q of MCP server %q", k, s.Name), v)
				}
			}
		}
	}

	// Example/template files legitimately contain fake values: only known formats count there.
	templateFile := templateFileRe.MatchString(path.Base(f.Path))
	for i, line := range f.Lines {
		n := i + 1
		if len(line) > 4000 {
			continue // minified / generated content
		}
		for _, p := range knownSecrets {
			if loc := p.re.FindStringIndex(line); loc != nil && !strings.Contains(line[loc[0]:loc[1]], "EXAMPLE") {
				add(n, finding.Critical, p.name, loc[0], loc[1])
				break
			}
		}
		if seen[n] || templateFile {
			continue
		}
		if m := connStringRe.FindStringSubmatchIndex(line); m != nil {
			pw, host := line[m[2]:m[3]], strings.ToLower(line[m[4]:m[5]])
			if !isPlaceholder(pw) && !trivialPasswords[strings.ToLower(pw)] && !devHostRe.MatchString(host) {
				add(n, finding.Critical, "Connection string with embedded password", m[2], m[3])
				continue
			}
		}
		if m := authHeaderRe.FindStringSubmatchIndex(line); m != nil && looksLikeSecret(line[m[2]:m[3]], 3.0) {
			add(n, finding.Critical, "Hard-coded Authorization header", m[2], m[3])
			continue
		}
		re, sev, kind := genericAssignRe, finding.High, "Possible hard-coded credential"
		if f.Language == source.Env {
			re, kind = envAssignRe, "Credential"
		}
		for _, m := range re.FindAllStringSubmatchIndex(line, -1) {
			if v := line[m[2]:m[3]]; len(v) >= 12 && looksLikeSecret(v, 3.0) && !namesItself(v) {
				add(n, sev, kind, m[2], m[3])
				break
			}
		}
	}
	return out
}

func describeFile(f *source.File) string {
	switch {
	case f.IsMCPConfig:
		return "MCP client configuration"
	case f.Language == source.Env:
		return "env file (make sure it is not committed)"
	case f.Language.IsCode():
		return "source code"
	}
	return "configuration file"
}

func isPlaceholder(v string) bool { return placeholderRe.MatchString(v) }

// namesItself catches values like "token-1" or "demo-client-secret": real secrets do not
// spell out what they are.
func namesItself(v string) bool {
	l := strings.ToLower(v)
	for _, w := range []string{"token", "secret", "password", "passwd", "apikey", "api_key", "api-key", "credential"} {
		if strings.Contains(l, w) {
			return true
		}
	}
	return false
}

// looksLikeSecret filters out placeholders, env var names, identifiers and low-entropy words.
func looksLikeSecret(v string, minEntropy float64) bool {
	if len(v) < 8 || isPlaceholder(v) || envVarNameRe.MatchString(v) {
		return false
	}
	switch strings.ToLower(v) {
	case "true", "false", "password", "required", "optional":
		return false
	}
	var lower, upper, digit, other bool
	for _, c := range v {
		switch {
		case unicode.IsLower(c):
			lower = true
		case unicode.IsUpper(c):
			upper = true
		case unicode.IsDigit(c):
			digit = true
		default:
			other = true
		}
	}
	// Real secrets mix character classes; "access_token" or "my-api-key" do not.
	letter, mixedCase := lower || upper, lower && upper
	if !mixedCase && (!letter || !digit) {
		return false
	}
	if other && !digit && !mixedCase {
		return false
	}
	return shannonEntropy(v) >= minEntropy
}

func shannonEntropy(s string) float64 {
	counts := map[rune]int{}
	n := 0
	for _, c := range s {
		counts[c]++
		n++
	}
	var h float64
	for _, c := range counts {
		p := float64(c) / float64(n)
		h -= p * math.Log2(p)
	}
	return h
}

// redact keeps a short prefix so the finding stays recognizable without leaking the secret.
func redact(s string) string {
	keep := min(4, len(s)/4)
	return s[:keep] + strings.Repeat("*", min(12, len(s)-keep))
}
