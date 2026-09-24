package extract

import (
	"regexp"
	"strings"

	"github.com/Gerijacki/mcp-guard/internal/source"
)

var (
	// server.tool("name", ...) and server.registerTool("name", {...}, handler)
	tsToolRe = regexp.MustCompile(`\.\s*(?:tool|registerTool)\s*\(`)
	// server.setRequestHandler(CallToolRequestSchema, async (request) => {...})
	tsCallHandlerRe = regexp.MustCompile(`setRequestHandler\s*\(\s*CallToolRequestSchema\s*,`)
	// { name: "x", description: "...", inputSchema: {...} } objects (list_tools style)
	tsNameKeyRe  = regexp.MustCompile(`\bname\s*:\s*`)
	tsDescribeRe = regexp.MustCompile(`\.describe\s*\(`)
	tsFuncDeclRe = `(?:function\s*\*?\s*%s\s*\(|(?:const|let|var)\s+%s\s*(?::[^=]+)?=\s*)`
)

func extractTypeScript(f *source.File) []source.Tool {
	s := f.Code()
	var tools []source.Tool

	for _, m := range tsToolRe.FindAllStringIndex(s, -1) {
		open := m[1] - 1
		close := source.MatchClose(s, open, source.TypeScript)
		if close < 0 {
			continue
		}
		args := source.SplitArgs(s, open+1, close, source.TypeScript)
		if len(args) < 2 {
			continue
		}
		name, _, ok := source.ParseStringLiteral(s, args[0].Start, source.TypeScript)
		if !ok {
			continue
		}
		t := source.Tool{Name: name, Line: f.LineAt(m[0])}
		last := args[len(args)-1]
		mid := s[args[0].End:last.Start]
		midStart := args[0].End
		if len(args) >= 3 {
			if d, end, ok := source.ParseStringLiteral(s, args[1].Start, source.TypeScript); ok && source.SkipSpace(s, end) >= args[1].End {
				t.Description, t.DescriptionLine = d, f.LineAt(source.SkipSpace(s, args[1].Start))
			}
		}
		if t.Description == "" {
			if d, off, ok := keyString(mid, "description", source.TypeScript); ok {
				t.Description, t.DescriptionLine = d, f.LineAt(midStart+off)
			}
		}
		t.Annotations = parseHints(mid)
		t.ParamDescriptions = allStrings(mid, tsDescribeRe, source.TypeScript)
		if params, from, to, ok := tsHandler(f, last.Start, last.End); ok {
			t.Params = params
			f.SetBody(&t, from, to)
		} else if ident := strings.TrimSpace(s[last.Start:last.End]); isIdent(ident) {
			if off, ok := tsResolveFunc(s, ident); ok {
				if params, from, to, ok := tsHandler(f, off, len(s)); ok {
					t.Params = params
					f.SetBody(&t, from, to)
				}
			}
		}
		tools = append(tools, t)
	}

	for _, m := range tsCallHandlerRe.FindAllStringIndex(s, -1) {
		open := m[0] + strings.IndexByte(s[m[0]:m[1]], '(')
		close := source.MatchClose(s, open, source.TypeScript)
		if close < 0 {
			continue
		}
		args := source.SplitArgs(s, open+1, close, source.TypeScript)
		if len(args) < 2 {
			continue
		}
		if params, from, to, ok := tsHandler(f, args[1].Start, args[1].End); ok {
			t := source.Tool{
				Name: "CallToolRequestSchema handler", Line: f.LineAt(m[0]), Dispatcher: true,
				Params: params, Annotations: map[string]string{},
			}
			f.SetBody(&t, from, to)
			tools = append(tools, t)
		}
	}

	// Plain tool definition objects: { name: "x", description: "...", inputSchema: ... }.
	names := tsNameKeyRe.FindAllStringIndex(s, -1)
	for i, m := range names {
		name, _, ok := source.ParseStringLiteral(s, m[1], source.TypeScript)
		if !ok || hasTool(tools, name) {
			continue
		}
		end := len(s)
		if i+1 < len(names) {
			end = names[i+1][0]
		}
		end = min(end, m[1]+4000)
		seg := s[m[1]:end]
		if !strings.Contains(seg, "inputSchema") && !strings.Contains(seg, "input_schema") {
			continue
		}
		t := source.Tool{Name: name, Line: f.LineAt(m[0]), Annotations: parseHints(seg)}
		if d, off, ok := keyString(seg, "description", source.TypeScript); ok {
			t.Description, t.DescriptionLine = d, f.LineAt(m[1]+off)
		}
		tools = append(tools, t)
	}
	return tools
}

// tsHandler parses a function expression in s[off:limit] (arrow function, function
// expression or declaration) and returns its parameter names and body byte range.
func tsHandler(f *source.File, off, limit int) ([]string, int, int, bool) {
	s := f.Code()
	i := source.SkipSpace(s, off)
	if strings.HasPrefix(s[i:], "async") && i+5 < len(s) && !isIdentByte(s[i+5]) {
		i = source.SkipSpace(s, i+5)
	}
	if strings.HasPrefix(s[i:], "function") {
		i = source.SkipSpace(s, i+len("function"))
		if i < len(s) && s[i] == '*' {
			i = source.SkipSpace(s, i+1)
		}
		for i < len(s) && isIdentByte(s[i]) {
			i++
		}
		i = source.SkipSpace(s, i)
	}
	if i >= len(s) {
		return nil, 0, 0, false
	}
	var params []string
	switch {
	case s[i] == '(':
		close := source.MatchClose(s, i, source.TypeScript)
		if close < 0 {
			return nil, 0, 0, false
		}
		params = jsParams(s[i+1 : close])
		i = close + 1
	case isIdentByte(s[i]):
		j := i
		for j < len(s) && isIdentByte(s[j]) {
			j++
		}
		params = []string{s[i:j]}
		i = j
	default:
		return nil, 0, 0, false
	}
	// Find the body: the first "=>" or "{" after the parameter list (skipping a return type).
	for j := i; j < len(s) && j < limit; j++ {
		switch {
		case s[j] == '=' && j+1 < len(s) && s[j+1] == '>':
			k := source.SkipSpace(s, j+2)
			if k < len(s) && s[k] == '{' {
				if close := source.MatchClose(s, k, source.TypeScript); close > 0 {
					return params, k + 1, close, true
				}
			}
			return params, k, max(k+1, limit), true
		case s[j] == '{':
			if close := source.MatchClose(s, j, source.TypeScript); close > 0 {
				return params, j + 1, close, true
			}
			return nil, 0, 0, false
		case s[j] == ';' || s[j] == ',':
			return nil, 0, 0, false
		}
	}
	return nil, 0, 0, false
}

// tsResolveFunc finds the declaration of a named handler function in the file.
func tsResolveFunc(s, name string) (int, bool) {
	q := regexp.QuoteMeta(name)
	re := regexp.MustCompile(strings.ReplaceAll(tsFuncDeclRe, "%s", q))
	loc := re.FindStringIndex(s)
	if loc == nil {
		return 0, false
	}
	if strings.HasPrefix(s[loc[0]:], "function") {
		return loc[0], true
	}
	return loc[1], true
}

// jsParams extracts parameter identifiers, flattening destructuring patterns:
// "({ path, content }: Args, extra)" -> [path content extra].
func jsParams(inner string) []string {
	var out []string
	for _, seg := range source.SplitArgs(inner, 0, len(inner), source.TypeScript) {
		p := strings.TrimPrefix(seg.Text(inner), "...")
		if p == "" {
			continue
		}
		if p[0] == '{' || p[0] == '[' {
			close := source.MatchClose(p, 0, source.TypeScript)
			if close < 0 {
				continue
			}
			pat := p[1:close]
			for _, part := range source.SplitArgs(pat, 0, len(pat), source.TypeScript) {
				q := strings.TrimPrefix(part.Text(pat), "...")
				if eq := strings.IndexByte(q, '='); eq >= 0 {
					q = q[:eq]
				}
				if colon := strings.IndexByte(q, ':'); colon >= 0 {
					out = append(out, source.Identifiers(q[colon+1:])...) // { path: p } binds p
					continue
				}
				if q = strings.TrimSpace(q); isIdent(q) {
					out = append(out, q)
				}
			}
			continue
		}
		j := 0
		for j < len(p) && isIdentByte(p[j]) {
			j++
		}
		if j > 0 {
			out = append(out, p[:j])
		}
	}
	return out
}

func isIdentByte(c byte) bool {
	return c == '_' || c == '$' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

func isIdent(s string) bool {
	if s == "" || (s[0] >= '0' && s[0] <= '9') {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isIdentByte(s[i]) {
			return false
		}
	}
	return true
}
