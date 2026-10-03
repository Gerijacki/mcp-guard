package extract

import (
	"regexp"
	"strings"

	"github.com/Gerijacki/mcp-guard/internal/source"
)

var (
	// @mcp.tool, @mcp.tool(), @server.tool(name=...), @app.call_tool(), @mcp.resource("uri"), @mcp.prompt()
	pyDecoratorRe = regexp.MustCompile(`(?m)^[ \t]*@[ \t]*[A-Za-z_][\w.]*\.(tool|call_tool|resource|prompt)\b`)
	// @tool / @tool(...) imported directly (fastmcp.tools.tool); only trusted in files that mention MCP.
	pyBareToolRe = regexp.MustCompile(`(?m)^[ \t]*@[ \t]*(tool)\b`)
	pyDefRe      = regexp.MustCompile(`(?m)^([ \t]*)(?:async[ \t]+)?def[ \t]+(\w+)[ \t]*\(`)
	// mcp.add_tool(fn, name=..., description=...) and Tool.from_function(fn, ...)
	pyAddToolRe = regexp.MustCompile(`(?:\.add_tool\s*\(\s*(\w+)\s*[,)]|\b(?:Function)?Tool\.from_function\s*\(\s*(\w+))`)
	// types.Tool(name=..., description=..., inputSchema=...) in list_tools handlers
	pyToolCtorRe  = regexp.MustCompile(`\b(?:types\.)?Tool\s*\(`)
	pyFieldDescRe = regexp.MustCompile(`\bdescription\s*=\s*`)
)

var pyReceiverRe = regexp.MustCompile(`@[ \t]*([A-Za-z_][\w.]*)\.\w+$`)

// pyReceiver returns "mcp" for the decorator text "@mcp.tool".
func pyReceiver(dec string) string {
	if m := pyReceiverRe.FindStringSubmatch(strings.TrimSpace(dec)); m != nil {
		return m[1]
	}
	return ""
}

type pyFunc struct {
	name               string
	line               int
	params             []string
	fixed              []string
	paramDescs         []string
	bodyStart, bodyEnd int // lines
	bodyFrom, bodyTo   int // offsets
	doc                string
	docLine            int
}

func extractPython(f *source.File) []source.Tool {
	s := f.Code()
	var tools []source.Tool

	k := f.Skeleton() // registrations inside strings (docstring examples) are not tools
	decorators := pyDecoratorRe.FindAllStringSubmatchIndex(k, -1)
	if strings.Contains(strings.ToLower(s), "mcp") {
		decorators = append(decorators, pyBareToolRe.FindAllStringSubmatchIndex(k, -1)...)
	}
	for _, m := range decorators {
		kind := s[m[2]:m[3]]
		after, argText, argStart := m[1], "", 0
		if j := source.SkipSpace(s, after); j < len(s) && s[j] == '(' && !strings.Contains(s[after:j], "\n") {
			if close := source.MatchClose(s, j, source.Python); close > 0 {
				argText, argStart, after = s[j+1:close], j+1, close+1
			}
		}
		loc := pyDefRe.FindStringSubmatchIndex(s[after:])
		if loc == nil {
			continue
		}
		for i := range loc {
			loc[i] += after
		}
		fn, ok := pyFunction(f, loc)
		if !ok {
			continue
		}
		t := source.Tool{
			FixedParams:       fn.fixed,
			Name:              fn.name,
			Description:       fn.doc,
			DescriptionLine:   fn.docLine,
			Params:            fn.params,
			ParamDescriptions: fn.paramDescs,
			Annotations:       parseHints(argText),
			Line:              f.LineAt(m[0]),
		}
		f.SetBody(&t, fn.bodyFrom, fn.bodyTo)
		t.Receiver = pyReceiver(s[m[0]:m[1]])
		switch kind {
		case "call_tool":
			t.Dispatcher, t.Description, t.DescriptionLine = true, "", 0
			t.Params = without(fn.params, "name")
		case "resource", "prompt":
			t.Kind = kind
		}
		if v, _, ok := keyString(argText, "name", source.Python); ok {
			t.Name = v
		}
		if v, off, ok := keyString(argText, "description", source.Python); ok {
			t.Description, t.DescriptionLine = v, f.LineAt(argStart+off)
		}
		t.DescriptionDynamic = t.Description == "" && hasKey(argText, "description")
		tools = append(tools, t)
	}

	for _, m := range pyAddToolRe.FindAllStringSubmatchIndex(k, -1) {
		g := 2
		if m[g] < 0 { // Tool.from_function(fn, ...) is the second alternative
			g = 4
		}
		name := s[m[g]:m[g+1]]
		defRe := cachedRegexp(`(?m)^([ \t]*)(?:async[ \t]+)?def[ \t]+(` + regexp.QuoteMeta(name) + `)[ \t]*\(`)
		loc := defRe.FindStringSubmatchIndex(s)
		if loc == nil {
			continue
		}
		fn, ok := pyFunction(f, loc)
		if !ok {
			continue
		}
		open := m[0] + strings.IndexByte(s[m[0]:m[1]], '(')
		argText := ""
		if close := source.MatchClose(s, open, source.Python); close > 0 {
			argText = s[open+1 : close]
		}
		t := source.Tool{
			Name: fn.name, Description: fn.doc, DescriptionLine: fn.docLine,
			Params: fn.params, FixedParams: fn.fixed, ParamDescriptions: fn.paramDescs, Annotations: parseHints(argText),
			Line: f.LineAt(m[0]),
		}
		f.SetBody(&t, fn.bodyFrom, fn.bodyTo)
		if v, _, ok := keyString(argText, "name", source.Python); ok {
			t.Name = v
		}
		if v, off, ok := keyString(argText, "description", source.Python); ok {
			t.Description, t.DescriptionLine = v, f.LineAt(open+1+off)
		}
		t.DescriptionDynamic = t.Description == "" && hasKey(argText, "description")
		if !hasTool(tools, t.Name) {
			tools = append(tools, t)
		}
	}

	// Metadata-only tool definitions (low-level Server.list_tools style).
	for _, m := range pyToolCtorRe.FindAllStringIndex(k, -1) {
		open := m[1] - 1
		close := source.MatchClose(s, open, source.Python)
		if close < 0 {
			continue
		}
		argText := s[open+1 : close]
		name, _, ok := keyString(argText, "name", source.Python)
		if !ok || hasTool(tools, name) {
			continue
		}
		t := source.Tool{Name: name, Line: f.LineAt(m[0]), Annotations: parseHints(argText),
			ParamDescriptions: schemaDescriptions(argText, source.Python)}
		if v, off, ok := keyString(argText, "description", source.Python); ok {
			t.Description, t.DescriptionLine = v, f.LineAt(open+1+off)
		}
		t.DescriptionDynamic = t.Description == "" && hasKey(argText, "description")
		tools = append(tools, t)
	}
	return tools
}

// pyFunction parses a def whose pyDefRe submatch indices (absolute offsets) are loc.
func pyFunction(f *source.File, loc []int) (pyFunc, bool) {
	s := f.Code()
	indent := source.Indent(s[loc[2]:loc[3]])
	fn := pyFunc{name: s[loc[4]:loc[5]], line: f.LineAt(loc[4])}
	open := loc[1] - 1
	close := source.MatchClose(s, open, source.Python)
	if close < 0 {
		return fn, false
	}
	sig := s[open+1 : close]
	fn.params = pyParams(sig)
	fn.fixed = pyFixedParams(sig)
	fn.paramDescs = allStrings(sig, pyFieldDescRe, source.Python)

	colon := strings.IndexByte(s[close:], ':')
	if colon < 0 {
		return fn, false
	}
	colonOff := close + colon
	colonLine := f.LineAt(colonOff)
	fn.bodyStart = colonLine + 1
	if rest := strings.TrimSpace(s[colonOff+1 : f.LineEnd(colonLine)]); rest != "" && !strings.HasPrefix(rest, "#") {
		fn.bodyStart = colonLine // one-liner: def f(x): return x
	}
	fn.bodyEnd = fn.bodyStart - 1
	for n := fn.bodyStart; n <= len(f.Lines); n++ {
		l := f.Line(n)
		t := strings.TrimSpace(l)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		if n > colonLine && source.Indent(l) <= indent {
			break
		}
		fn.bodyEnd = n
	}
	if fn.bodyEnd < fn.bodyStart {
		return fn, false
	}
	fn.bodyFrom, fn.bodyTo = f.LineStart(fn.bodyStart), f.LineEnd(fn.bodyEnd)
	if fn.bodyStart == colonLine {
		fn.bodyFrom = colonOff + 1
	}

	// Docstring: the first statement of the body, if it is a string literal.
	for n := fn.bodyStart; n <= fn.bodyEnd; n++ {
		t := strings.TrimSpace(f.Line(n))
		if t == "" {
			continue
		}
		if n == colonLine {
			break
		}
		if strings.IndexAny(t[:1], `"'`) == 0 || (len(t) > 1 && strings.IndexAny(t[:1], "rRuU") == 0 && strings.IndexAny(t[1:2], `"'`) == 0) {
			off := f.LineStart(n) + strings.Index(f.Line(n), t[:1])
			if v, _, ok := source.ParseStringLiteral(s, off, source.Python); ok {
				fn.doc, fn.docLine = cleanDoc(v), n
			}
		}
		break
	}
	return fn, true
}

// pyParams returns parameter names from a def signature, skipping self/cls and the
// MCP Context parameter (which is injected by the framework, not by the model).
var pyFixedTypeRe = regexp.MustCompile(`^\s*:\s*(?:typing\.)?(?:Optional\[\s*)?(?:Literal\[|int\b|float\b|bool\b|Decimal\b|Enum\b)`)

// pyFixedParams returns the parameters annotated with a type that cannot hold a payload:
// int, float, bool, Literal[...] (also Optional[...] of those, and "int | None").
func pyFixedParams(sig string) []string {
	var out []string
	for _, seg := range source.SplitArgs(sig, 0, len(sig), source.Python) {
		p := strings.TrimLeft(seg.Text(sig), "*")
		i := strings.IndexAny(p, ":=")
		if i < 0 || p[i] != ':' {
			continue
		}
		if pyFixedTypeRe.MatchString(p[i:]) {
			out = append(out, strings.TrimSpace(p[:i]))
		}
	}
	return out
}

func pyParams(sig string) []string {
	var out []string
	for _, seg := range source.SplitArgs(sig, 0, len(sig), source.Python) {
		p := strings.TrimLeft(seg.Text(sig), "*")
		name, annot := p, ""
		if i := strings.IndexAny(p, ":="); i >= 0 {
			name, annot = p[:i], p[i:]
		}
		name = strings.TrimSpace(name)
		switch name {
		case "", "self", "cls", "/", "ctx", "context":
			continue
		}
		if strings.Contains(annot, "Context") {
			continue
		}
		out = append(out, name)
	}
	return out
}

func cleanDoc(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	for i, l := range lines {
		lines[i] = strings.TrimSpace(l)
	}
	return strings.Join(lines, "\n")
}

func without(xs []string, drop string) []string {
	var out []string
	for _, x := range xs {
		if x != drop {
			out = append(out, x)
		}
	}
	return out
}
