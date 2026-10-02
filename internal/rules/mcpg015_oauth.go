package rules

import (
	"regexp"

	"github.com/Gerijacki/mcp-guard/internal/finding"
	"github.com/Gerijacki/mcp-guard/internal/source"
)

// MCPG015: OAuth misuse in an MCP server: wildcard/admin scopes and forwarding the
// client's access token to another API (token passthrough).
type oauthRule struct{}

var (
	broadScopeRe = regexp.MustCompile(`\b(?:required_scopes|requiredScopes|scopes?|SCOPES?|REQUIRED_SCOPES)\b["']?\s*[:=]\s*[\[(]?\s*["'][^"'\n]*(?:(?:^|[\s,:"'])\*(?:$|[\s,:"'])|\badmin\b|\bfull[_-]?access\b|\.default\b|\broot\b|:\*)[^"'\n]*["']`)
	// The access token of the incoming MCP request.
	incomingAuthRe = regexp.MustCompile(`(?i)(?:\b(?:request|req|ctx|context|self\.request|request_context)\b[\w.\[\]()"']*\.headers[\w.\[\]()"']*(?:\[\s*|\.get\s*\(\s*)["']authorization["']|\bheaders\.authorization\b|\bheaders\[\s*["']authorization["']\s*\]|\.Header\.Get\s*\(\s*"Authorization"\s*\)|\bget_access_token\s*\(\s*\))`)
	outboundRe     = regexp.MustCompile(`\b(?:requests|httpx)\.\w+\s*\(|\b(?:client|session|http)\.(?:get|post|put|patch|delete|request)\s*\(|(?:^|[^.\w$])fetch\s*\(|\baxios\b|\bhttp\.(?:NewRequest\w*|Get|Post)\s*\(|\.Header\.Set\s*\(\s*"Authorization"`)
)

func (oauthRule) Meta() Meta {
	return Meta{
		ID:       "MCPG015",
		Name:     "oauth-scope-or-token-misuse",
		Severity: finding.Medium,
		Summary:  "Wildcard OAuth scope, or the client's access token forwarded to another API",
		Description: "The server requests a wildcard or administrator OAuth scope, or takes the access token it " +
			"received from the MCP client and sends it on to a downstream API (token passthrough). The MCP " +
			"authorization specification forbids passthrough: the downstream service cannot tell the token was " +
			"issued for a different audience, audit trails break, and a compromised MCP server can replay the " +
			"token. Over-broad scopes turn every prompt injection into account-wide access.",
		Remediation: "Request the narrowest scopes the tools need and split read and write. Validate that incoming tokens " +
			"were issued for this server (audience), and obtain a separate token for downstream APIs (token " +
			"exchange or the server's own credentials).",
		CWE:   []string{"CWE-269", "CWE-285"},
		OWASP: []string{"MCP02:2025", "LLM06:2025", "ASI03:2026"},
	}
}

func (r oauthRule) Check(f *source.File) []finding.Finding {
	if !f.Language.IsCode() {
		return nil
	}
	if !containsAny(f.Content, "scope", "Scope", "SCOPE", "uthorization", "AccessToken", "access_token") {
		return nil
	}
	var out []finding.Finding
	stmts := f.StatementsIn(0, len(f.Content))
	tokens := newTaintSet(nil) // variables holding the incoming access token
	for _, st := range stmts {
		if broadScopeRe.MatchString(st.Text) {
			out = append(out, newFinding(r.Meta(), f, st.Line, finding.Medium, "",
				"OAuth scope is a wildcard or administrator scope: grant only the permissions the tools need."))
			continue
		}
		if a, ok := parseAssign(st.Text); ok && incomingAuthRe.MatchString(a.rhs) {
			for _, id := range a.ids {
				tokens.add(id)
			}
		}
		if !outboundRe.MatchString(st.Text) {
			continue
		}
		if incomingAuthRe.MatchString(st.Text) || (tokens.find(st.Text) != "" && authWordRe.MatchString(st.Text)) {
			out = append(out, newFinding(r.Meta(), f, st.Line, finding.Medium, "",
				"The access token received from the MCP client is forwarded to another API (token passthrough): use a separate downstream credential."))
		}
	}
	return out
}

var authWordRe = regexp.MustCompile(`(?i)authorization|bearer|token`)
