package rules

import (
	"regexp"
	"strings"

	"github.com/Gerijacki/mcp-guard/internal/finding"
	"github.com/Gerijacki/mcp-guard/internal/source"
)

// MCPG008: an HTTP/SSE MCP transport listens on all interfaces without authentication.
type transportRule struct{}

var (
	httpTransportRe = regexp.MustCompile(`(?i)SSEServerTransport|StreamableHTTPServerTransport|\bsse_app\b|streamable_http_app|transport\s*=\s*["'](?:sse|streamable-http|http)["']|\.run\s*\(\s*["'](?:sse|streamable-http|http)["']|NewSSEServer|NewStreamableHTTPServer|NewSSEHandler|NewStreamableHTTPHandler|StreamableHTTPHandler|\bSSEHandler\b`)
	allInterfacesRe = []*regexp.Regexp{
		regexp.MustCompile(`["'](?:0\.0\.0\.0|::|\[::\])(?::\d+)?["']`),
		// Go: ListenAndServe(":8080") / sseServer.Start(":8080") bind every interface.
		regexp.MustCompile(`\b(?:ListenAndServe(?:TLS)?|Start|Listen)\s*\(\s*(?:"tcp[46]?"\s*,\s*)?":\d+"`),
		// Node: app.listen(port) / app.listen(port, callback) without a host.
		regexp.MustCompile(`\.listen\s*\(\s*[\w.]+\s*(?:\)|,\s*(?:\(|function\b|async\b|\w+\s*=>))`),
	}
	authEvidenceRe = regexp.MustCompile(`(?i)\bauth(?:enticat|oriz|[_-]|Middleware|Provider|Settings|Handler|\b)|bearer|api[_-]?key|\bjwt\b|oauth|token[_-]?verifier|verify[_-]?token|basicauth|x-api-key|passport\b|requireAuth|\bclerk\b`)
)

func (transportRule) Meta() Meta {
	return Meta{
		ID:       "MCPG008",
		Name:     "exposed-network-transport",
		Severity: finding.Medium,
		Summary:  "HTTP/SSE MCP transport bound to all interfaces without authentication",
		Description: "The server exposes MCP over HTTP or SSE on 0.0.0.0 (or an unqualified port, which " +
			"binds every interface) and no authentication is visible in the file. Anyone on the same " +
			"network, or the internet if the port is reachable, can list and call its tools directly, " +
			"bypassing the client's confirmation prompts. Local servers are also exposed to DNS-rebinding " +
			"attacks from malicious web pages.",
		Remediation: "Bind to 127.0.0.1 for local use. When remote access is needed, require authentication " +
			"(MCP authorization / OAuth 2.1, or at least a bearer token checked on every request), validate " +
			"the Origin and Host headers, and put the server behind TLS.",
		CWE: []string{"CWE-306", "CWE-1327"},
	}
}

func (r transportRule) Check(f *source.File) []finding.Finding {
	if !f.Language.IsCode() || !httpTransportRe.MatchString(f.Content) || authEvidenceRe.MatchString(f.Content) {
		return nil
	}
	for i, line := range f.Lines {
		if t := strings.TrimSpace(line); strings.HasPrefix(t, "#") || strings.HasPrefix(t, "//") || strings.HasPrefix(t, "*") {
			continue
		}
		for _, re := range allInterfacesRe {
			if re.MatchString(line) {
				return []finding.Finding{newFinding(r.Meta(), f, i+1, finding.Medium, "",
					"MCP server is reachable on all network interfaces over HTTP/SSE and no authentication was found.")}
			}
		}
	}
	return nil
}
