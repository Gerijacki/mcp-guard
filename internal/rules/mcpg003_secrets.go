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
	{"PyPI token", regexp.MustCompile(`\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,}`)},
	{"Groq API key", regexp.MustCompile(`\bgsk_[A-Za-z0-9]{40,}\b`)},
	{"OpenRouter API key", regexp.MustCompile(`\bsk-or-v1-[a-f0-9]{64}\b`)},
	{"Supabase access token", regexp.MustCompile(`\bsbp_[a-f0-9]{40}\b`)},
	{"DigitalOcean token", regexp.MustCompile(`\bdop_v1_[a-f0-9]{64}\b`)},
	{"Docker Hub token", regexp.MustCompile(`\bdckr_pat_[A-Za-z0-9_\-]{27,}`)},
	{"Replicate API token", regexp.MustCompile(`\br8_[A-Za-z0-9]{37}\b`)},
	{"Perplexity API key", regexp.MustCompile(`\bpplx-[A-Za-z0-9]{40,}\b`)},
	{"Google OAuth access token", regexp.MustCompile(`\bya29\.[A-Za-z0-9_\-]{50,}`)},
	{"Discord bot token", regexp.MustCompile(`\b[MNO][A-Za-z0-9]{23,25}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27,}\b`)},
	{"JSON Web Token", regexp.MustCompile(`\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}`)},
	{"Private key", regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----`)},
}

// knownHints lists, per known format, literals one of which must appear in a line for the
// format's regular expression to be worth running (a substring test is far cheaper).
var knownHints = map[string][]string{
	"Anthropic API key": {"sk-ant-"}, "OpenAI API key": {"sk-"}, "GitHub token": {"ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"},
	"GitLab token": {"glpat-"}, "AWS access key ID": {"AKIA", "ASIA", "ABIA", "ACCA"}, "Slack token": {"xox"},
	"Slack webhook URL": {"hooks.slack.com"}, "Stripe live key": {"sk_live_", "rk_live_"}, "Google API key": {"AIza"},
	"Hugging Face token": {"hf_"}, "npm token": {"npm_"}, "Notion token": {"ntn_"}, "Linear API key": {"lin_api_"},
	"SendGrid API key": {"SG."}, "PyPI token": {"pypi-"}, "Groq API key": {"gsk_"}, "OpenRouter API key": {"sk-or-v1-"},
	"Supabase access token": {"sbp_"}, "DigitalOcean token": {"dop_v1_"}, "Docker Hub token": {"dckr_pat_"},
	"Replicate API token": {"r8_"}, "Perplexity API key": {"pplx-"}, "Google OAuth access token": {"ya29."},
	"JSON Web Token": {"eyJ"}, "Private key": {"-----BEGIN"},
}

var (
	// key = "value" / "key": "value" where the key name looks like a credential.
	genericAssignRe = regexp.MustCompile(`(?i)[\w.-]*?(?:api[_-]?key|apikey|secret|token|passw(?:or)?d|pwd|auth[_-]?token|credentials?|private[_-]?key|access[_-]?key|client[_-]?secret)(?:[_.-][\w.-]*)?["']?\s*(?::=|[:=])\s*["']([^"'\s]{8,})["']`)
	// key: value in YAML/TOML-less formats where the value is not quoted (docker-compose, k8s).
	yamlAssignRe = regexp.MustCompile(`(?i)^\s*-?\s*[\w.-]*?(?:api[_-]?key|apikey|secret|token|passw(?:or)?d|pwd|auth[_-]?token|private[_-]?key|access[_-]?key|client[_-]?secret)[\w.-]*\s*:\s*([^\s"'#{$<][^\s#]{7,})\s*(?:#.*)?$`)
	// Credential-looking flag in a client config's args: --api-key=abc / "--token", "abc".
	secretFlagRe = regexp.MustCompile(`(?i)^--?[\w-]*(?:api[_-]?key|apikey|secret|token|passw(?:or)?d|auth|bearer|credentials?)[\w-]*$`)
	// ?api_key=abc in an MCP server URL.
	urlSecretRe = regexp.MustCompile(`(?i)[?&;](?:api[_-]?key|apikey|access[_-]?token|auth[_-]?token|token|key|secret|password|sig|signature)=([^&\s"'#]{12,})`)
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
	// Keys that are public by design (client-side ingest and publishable keys).
	publicKeyRe = regexp.MustCompile(`^(?:phc_|pk_(?:live|test)_|pub_[A-Za-z0-9]{8})`)
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

	// Credentials passed on the command line or in the URL of a client config entry.
	for _, s := range f.Servers {
		for i, a := range s.Args {
			flag, v := a, ""
			if eq := strings.IndexByte(a, '='); eq > 0 && strings.HasPrefix(a, "-") {
				flag, v = a[:eq], a[eq+1:]
			} else if i+1 < len(s.Args) {
				v = s.Args[i+1]
			}
			if secretFlagRe.MatchString(flag) && len(v) >= 12 && looksLikeSecret(v, 3.0) && !strings.HasPrefix(v, "-") && !strings.Contains(v, "/") {
				addValue(f.FindLine(v, s.Line), finding.Critical,
					fmt.Sprintf("Literal credential passed as %q in args of MCP server %q", flag, s.Name), v)
			}
		}
		if m := urlSecretRe.FindStringSubmatch(s.URL); m != nil && looksLikeSecret(m[1], 3.0) {
			addValue(f.FindLine(m[1], s.Line), finding.Critical,
				fmt.Sprintf("Credential embedded in the URL of MCP server %q (it ends up in logs and history)", s.Name), m[1])
		}
	}

	// Example/template files legitimately contain fake values: only known formats count there.
	templateFile := templateFileRe.MatchString(path.Base(f.Path))
	// The generic layers below read the code with comments and multi-line strings blanked: a
	// docstring or JSDoc example such as `clientSecret: 'my-idp-secret'` is documentation. Known token formats are matched
	// on the raw line, since a real key pasted into a comment is still a leaked key.
	codeLines := strings.Split(source.MaskMultilineStrings(f.Code(), f.Language), "\n")
	for i, raw := range f.Lines {
		n := i + 1
		if len(raw) > 4000 {
			continue // minified / generated content
		}
		for _, p := range knownSecrets {
			if hints := knownHints[p.name]; hints != nil && !containsAny(raw, hints...) {
				continue
			}
			if loc := p.re.FindStringIndex(raw); loc != nil && !strings.Contains(raw[loc[0]:loc[1]], "EXAMPLE") {
				add(n, finding.Critical, p.name, loc[0], loc[1])
				break
			}
		}
		if seen[n] || templateFile {
			continue
		}
		line := raw
		if i < len(codeLines) && len(codeLines[i]) == len(raw) {
			line = codeLines[i]
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
		switch f.Language {
		case source.Env:
			re, kind = envAssignRe, "Credential"
		case source.YAML:
			re = yamlAssignRe
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
	if len(v) < 8 || isPlaceholder(v) || envVarNameRe.MatchString(v) || publicKeyRe.MatchString(v) {
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
