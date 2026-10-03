package rules

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/Gerijacki/mcp-guard/internal/finding"
	"github.com/Gerijacki/mcp-guard/internal/source"
)

// MCPG009: a tool parameter chooses the host of an outgoing HTTP request (SSRF).
type ssrfRule struct{ ext extension }

type ssrfSink struct {
	re *regexp.Regexp
	// urlArgs lists the call arguments that may carry the URL (the first match wins).
	urlArgs []int
}

var ssrfSinks = map[source.Language][]ssrfSink{
	source.Python: {
		{re: regexp.MustCompile(`\b(?:requests|httpx)\.(?:get|post|put|patch|delete|head|options|stream)\s*\(`), urlArgs: []int{0}},
		{re: regexp.MustCompile(`\b(?:requests|httpx)\.request\s*\(`), urlArgs: []int{1, 0}},
		{re: regexp.MustCompile(`\b(?:client|session|http|http_client|async_client)\.(?:get|post|put|patch|delete|head|options|stream)\s*\(`), urlArgs: []int{0}},
		{re: regexp.MustCompile(`\b(?:client|session|http|http_client|async_client)\.request\s*\(`), urlArgs: []int{1, 0}},
		{re: regexp.MustCompile(`\burlopen\s*\(|\burllib\.request\.Request\s*\(|\burllib3\.PoolManager\(\)\.request\s*\(`), urlArgs: []int{0, 1}},
		{re: regexp.MustCompile(`\.goto\s*\(`), urlArgs: []int{0}},
	},
	source.TypeScript: {
		{re: regexp.MustCompile(`(?:^|[^.\w$])fetch\s*\(|\baxios(?:\.(?:get|post|put|patch|delete|head|request))?\s*\(|\bgot(?:\.(?:get|post|put|patch|delete|stream))?\s*\(|\bky(?:\.(?:get|post|put|patch|delete))?\s*\(|\bundici\.(?:request|fetch)\s*\(|\bnode-?fetch\s*\(|\bsuperagent\.(?:get|post|put|delete)\s*\(`), urlArgs: []int{0}},
		{re: regexp.MustCompile(`\bhttps?\.(?:get|request)\s*\(`), urlArgs: []int{0}},
		{re: regexp.MustCompile(`\.goto\s*\(`), urlArgs: []int{0}},
	},
	source.Go: {
		{re: regexp.MustCompile(`\bhttp\.(?:Get|Head)\s*\(|\bhttp\.(?:Post|PostForm)\s*\(|\bhttp\.DefaultClient\.(?:Get|Head|Post)\s*\(|\b(?:client|httpClient)\.(?:Get|Head|Post|PostForm)\s*\(`), urlArgs: []int{0}},
		{re: regexp.MustCompile(`\bhttp\.NewRequest\s*\(`), urlArgs: []int{1}},
		{re: regexp.MustCompile(`\bhttp\.NewRequestWithContext\s*\(`), urlArgs: []int{2}},
	},
}

var (
	// Evidence that the destination is restricted: allowlists, private-address checks, SSRF helpers.
	ssrfGuardRe = regexp.MustCompile(`(?i)allow(?:ed)?[_-]?(?:hosts?|domains?|urls?|origins?|list|schemes?)|\bALLOWED_\w+|whitelist|is_?private|is_?global|is_?loopback|\bipaddress\.|ip_?address\s*\(|\bisIP\s*\(|private[_-]?ip|ssrf|safe_?(?:url|fetch|request|get)|validate_?(?:url|host|domain)|is_?(?:safe|allowed)_?(?:url|host|domain)|dns\.lookup|getaddrinfo|blocklist|denylist|netip\.`)
	// A literal scheme and authority at the start of the URL: only what follows "https://" up
	// to the first "/" decides the destination.
	literalOriginRe = regexp.MustCompile("^(?:[fFrRbB]{0,2})[\"'`]https?://([^/?#\"'`]*)")
	urlKeywordRe    = regexp.MustCompile(`^\s*(?:url|uri|endpoint|target)\s*=\s*([\s\S]*)$`)
)

func (ssrfRule) Meta() Meta {
	return Meta{
		ID:       "MCPG009",
		Name:     "server-side-request-forgery",
		Severity: finding.High,
		Summary:  "Tool parameter chooses the destination of an outgoing HTTP request",
		Description: "A model-controlled value is used as the URL (or its host) of an HTTP request made by the " +
			"server. The model, or a prompt injection it has read, can point the server at internal services " +
			"that the user's machine or network can reach but the agent should not: cloud metadata endpoints " +
			"(169.254.169.254), localhost admin panels, databases, other MCP servers. The response is then " +
			"returned to the model, so the attacker can read it.",
		Remediation: "Restrict destinations: parse the URL, require https and a host in an explicit allowlist, " +
			"resolve the host and refuse private, loopback and link-local addresses (and check again after " +
			"redirects, or disable them). If the tool only needs one API, build the URL from a constant base " +
			"and pass the model's value as a path or query parameter.",
		CWE:   []string{"CWE-918"},
		OWASP: []string{"MCP02:2025", "LLM06:2025", "ASI02:2026"},
	}
}

func (r ssrfRule) Check(f *source.File) []finding.Finding {
	return r.CheckTools(f, taintBodies(f))
}

// CheckTools runs the rule on the given tools (the file's tools plus helper views).
func (r ssrfRule) CheckTools(f *source.File, tools []source.Tool) []finding.Finding {
	sinks := ssrfSinks[f.Language]
	if sinks == nil {
		return nil
	}
	guardRe := r.ext.withSanitizers(ssrfGuardRe)
	if r.ext.sinks != nil {
		sinks = append(append([]ssrfSink(nil), sinks...), ssrfSink{re: r.ext.sinks, urlArgs: []int{0}})
	}
	if r.ext.sinks == nil && !containsAny(f.Content, "http", "fetch", "axios", "got", "ky", "undici", "superagent", "goto", "urlopen", "request") {
		return nil
	}
	var out []finding.Finding
	for _, t := range tools {
		if guardRe.MatchString(f.CodeText(t)) {
			continue
		}
		walkTaintWith(f, t, guardRe, ssrfPropagates, func(st source.Stmt, taint *taintSet) {
			for _, s := range sinks {
				loc := s.re.FindStringIndex(st.Text)
				if loc == nil {
					continue
				}
				args := callArgs(st.Text, loc[1]-1, f.Language)
				p := ""
				for _, i := range s.urlArgs {
					if i < len(args) {
						if p = urlHostTainted(args[i], taint); p != "" {
							break
						}
					}
				}
				if p == "" {
					for _, a := range args { // url=... keyword argument
						if m := urlKeywordRe.FindStringSubmatch(a); m != nil {
							if p = urlHostTainted(m[1], taint); p != "" {
								break
							}
						}
					}
				}
				if p == "" {
					continue
				}
				sev, extra := finding.High, ""
				if followsRedirects(st.Text) {
					sev, extra = finding.Critical, " and follows redirects"
				}
				out = append(out, newFinding(r.Meta(), f, st.Line, sev, t.Name, fmt.Sprintf(
					"%s %q sends an HTTP request to a URL controlled by the model (%q)%s without restricting hosts (server-side request forgery).",
					t.Noun(), t.Name, p, extra)))
				return
			}
		})
	}
	return out
}

// urlHostTainted returns the tainted identifier that decides where the URL points, or "".
// Only the host matters: `"https://api.example.com/" + id`, `${BASE}/items/${id}` and
// f"{BASE}/items/{id}" are controlled through their path, not through where they point.
func urlHostTainted(arg string, taint *taintSet) string {
	arg = strings.TrimSpace(arg)
	arg = strings.TrimSpace(strings.TrimPrefix(arg, "await "))
	if constTableRe.MatchString(arg) {
		return "" // SOURCE_URLS[key]: a lookup in a fixed table is an allowlist
	}
	if m := literalOriginRe.FindStringSubmatch(arg); m != nil {
		authority := m[1]
		switch {
		case strings.ContainsAny(authority, "{%$"): // "https://{host}/x", "https://%s/x", "https://${host}/x"
			return taint.find(arg)
		case authority == "": // "https://" + host + "/x": what follows the scheme literal is the host
			rest := arg[len(m[0]):]
			if rest != "" && (rest[0] == '"' || rest[0] == '\'' || rest[0] == '`') {
				rest = rest[1:] // the closing quote of the scheme literal
			}
			return taint.find(urlHostPart(rest))
		}
		return ""
	}
	// base + path: the first operand decides the host when it is a plain variable.
	if first := firstOperand(arg); first != "" && plainOperandRe.MatchString(first) {
		return taint.find(first)
	}
	return taint.find(urlHostPart(arg))
}

var plainOperandRe = regexp.MustCompile(`^[A-Za-z_$][\w$.]*$`)

// firstOperand returns the text before the first top-level "+" of expr (outside strings and
// brackets), or "" when there is none.
func firstOperand(expr string) string {
	var quote byte
	depth := 0
	for i := 0; i < len(expr); i++ {
		c := expr[i]
		switch {
		case quote != 0:
			switch c {
			case '\\':
				i++
			case quote:
				quote = 0
			}
		case c == '"' || c == '\'' || c == '`':
			quote = c
		case c == '(' || c == '[' || c == '{':
			depth++
		case c == ')' || c == ']' || c == '}':
			depth--
		case c == '+' && depth == 0:
			return strings.TrimSpace(expr[:i])
		}
	}
	return ""
}

// urlHostPart returns the leading part of a URL-building expression, up to the first slash
// that is part of a string literal (the end of the host). Interpolated and concatenated
// values before that slash are part of it; everything after it is path, query or fragment.
// An expression without such a slash is returned whole.
func urlHostPart(expr string) string {
	var quote byte
	interp := 0 // depth inside ${...} or {...} interpolations of a quoted string
	for i := 0; i < len(expr); i++ {
		c := expr[i]
		switch {
		case quote == 0:
			if c == '"' || c == '\'' || c == '`' {
				quote = c
			}
		case interp > 0:
			switch c {
			case '{':
				interp++
			case '}':
				interp--
			}
		case c == '\\':
			i++
		case c == quote:
			quote = 0
		case c == '{' || (c == '$' && i+1 < len(expr) && expr[i+1] == '{'):
			if c == '$' {
				i++
			}
			interp = 1
		case c == '/':
			return expr[:i]
		}
	}
	return expr
}

// ssrfPropagates decides whether an assignment passes taint on for MCPG009. Building a URL
// from a constant (or untainted) host and a tainted path does not make the result a
// model-chosen destination; anything else keeps the default behavior.
func ssrfPropagates(rhs string, taint *taintSet) bool {
	r := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(rhs), "await "))
	if constTableRe.MatchString(r) {
		return false
	}
	if !urlBuildRe.MatchString(r) {
		return true
	}
	return urlHostTainted(r, taint) != ""
}

// constTableRe matches an index into an upper-case constant table: URLS[key], URLS.get(key).
var constTableRe = regexp.MustCompile(`^[A-Z][A-Z0-9_]{2,}\s*(?:\[|\.get\s*\()`)

// urlBuildRe matches string-building expressions: a string, f-string or template literal, or
// a concatenation that starts with a variable and a string.
var urlBuildRe = regexp.MustCompile("^(?:[fFrRbB]{0,2}[\"'`]|[A-Za-z_$][\\w$.]*\\s*\\+\\s*[\"'`])")

var followRe = regexp.MustCompile(`(?i)follow_redirects\s*=\s*True|allow_redirects\s*=\s*True|\bredirect\s*:\s*['"]follow['"]|maxRedirects\s*:\s*(?:[1-9]|\d{2,})`)

func followsRedirects(stmt string) bool { return followRe.MatchString(stmt) }
