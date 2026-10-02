package rules

import (
	"regexp"
	"strings"

	"github.com/Gerijacki/mcp-guard/internal/finding"
	"github.com/Gerijacki/mcp-guard/internal/source"
)

// MCPG014: TLS certificate verification is switched off.
type insecureTLSRule struct{}

var tlsOffRes = compileByLang(map[source.Language]string{
	source.Python:     `\bverify\s*=\s*False\b|\bssl\._create_unverified_context\b|\bssl\.CERT_NONE\b|\bcheck_hostname\s*=\s*False\b`,
	source.TypeScript: `\brejectUnauthorized\s*[:=]\s*false\b|\bstrictSSL\s*[:=]\s*false\b`,
	source.Go:         `\bInsecureSkipVerify\s*[:=]\s*true\b`,
})

// The one setting whose value is a string, so it is matched with strings intact.
var nodeTLSEnvRe = regexp.MustCompile(`\bNODE_TLS_REJECT_UNAUTHORIZED\W{1,6}0\b`)

var localTargetRe = regexp.MustCompile(`(?i)localhost|127\.0\.0\.1|\[::1\]`)

func (insecureTLSRule) Meta() Meta {
	return Meta{
		ID:       "MCPG014",
		Name:     "tls-verification-disabled",
		Severity: finding.Medium,
		Summary:  "TLS certificate verification is disabled",
		Description: "The code turns off certificate or hostname verification (`verify=False`, `rejectUnauthorized: false`, " +
			"`InsecureSkipVerify: true`, `NODE_TLS_REJECT_UNAUTHORIZED=0`). Anyone on the network path can then " +
			"impersonate the remote service, read the API keys and tokens the server sends and rewrite the " +
			"responses that flow back into the model's context.",
		Remediation: "Remove the override and trust the system CA store. For a private CA, pass its certificate " +
			"(`verify=\"/path/ca.pem\"`, the `ca` option, `RootCAs`). Never disable verification in code that " +
			"also handles credentials.",
		CWE:   []string{"CWE-295"},
		OWASP: []string{"MCP07:2025", "ASI03:2026"},
	}
}

func (r insecureTLSRule) Check(f *source.File) []finding.Finding {
	re := tlsOffRes[f.Language]
	if re == nil {
		return nil
	}
	if !containsAny(f.Content, "verify", "rejectUnauthorized", "NODE_TLS", "strictSSL", "InsecureSkipVerify", "_create_unverified_context", "CERT_NONE", "check_hostname") {
		return nil
	}
	var out []finding.Finding
	code := strings.Split(f.Code(), "\n")
	// Matching on masked text keeps regexes, messages and docs that merely mention the
	// settings from being reported.
	masked := strings.Split(source.MaskStrings(f.Code(), f.Language), "\n")
	for i, line := range masked {
		if len(line) > 4000 || localTargetRe.MatchString(code[i]) {
			continue
		}
		if !re.MatchString(line) && (f.Language != source.TypeScript || !nodeTLSEnvRe.MatchString(code[i])) {
			continue
		}
		out = append(out, newFinding(r.Meta(), f, i+1, finding.Medium, "",
			"TLS certificate verification is disabled: a network attacker can impersonate the remote service and read or alter its traffic."))
		if len(out) == 3 {
			break
		}
	}
	return out
}
