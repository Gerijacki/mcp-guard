package extract

import (
	"regexp"
	"strings"

	"github.com/Gerijacki/mcp-guard/internal/source"
)

var (
	// s.AddTool(tool, handler) (mark3labs/mcp-go) and mcp.AddTool(server, tool, handler) (go-sdk)
	// plus AddPrompt / AddResource / AddResourceTemplate for the other MCP primitives.
	goAddToolRe = regexp.MustCompile(`\bAdd(Tool|Prompt|ResourceTemplate|Resource)\s*(?:\[[^\]]*\])?\s*\(`)
	// mcp.NewTool("name", ...) and &mcp.Tool{Name: ...}; NewPrompt/NewResource and literals likewise.
	goNewToolRe    = regexp.MustCompile(`\bNew(?:Tool|Prompt|ResourceTemplate|Resource)\s*\(`)
	goToolLitRe    = regexp.MustCompile(`\bmcp\.(?:Tool|Prompt|Resource|ResourceTemplate)\s*\{`)
	goWithDescRe   = regexp.MustCompile(`\bWith(?:Prompt|Resource|ResourceTemplate)?Description\s*\(`)
	goParamDescRe  = regexp.MustCompile(`\bDescription\s*\(`)
	goFuncLitRe    = regexp.MustCompile(`^func\s*\(`)
	goFuncDeclTmpl = `\bfunc\s+(?:\([^)]*\)\s*)?%s\s*(?:\[[^\]]*\])?\s*\(`
)

func extractGo(f *source.File) []source.Tool {
	s := f.Code()
	var tools []source.Tool
	consumed := map[int]bool{} // start offsets of tool definitions already paired with a handler

	for _, m := range goAddToolRe.FindAllStringSubmatchIndex(f.Skeleton(), -1) {
		kind := ""
		switch s[m[2]:m[3]] {
		case "Prompt":
			kind = "prompt"
		case "Resource", "ResourceTemplate":
			kind = "resource"
		}
		m = []int{m[0], m[1]}
		if goDeclaresMethod(s, m[0]) {
			continue // `func (s *Server) AddTool(t *Tool, h Handler)` defines the API, it registers nothing
		}
		open := m[1] - 1
		close := source.MatchClose(s, open, source.Go)
		if close < 0 {
			continue
		}
		args := source.SplitArgs(s, open+1, close, source.Go)
		if len(args) < 2 {
			continue
		}
		toolArg, handlerArg := args[len(args)-2], args[len(args)-1]
		if goParamDeclRe.MatchString(strings.TrimSpace(toolArg.Text(s))) {
			continue // an interface method or declaration: "t *Tool"
		}
		t := source.Tool{Line: f.LineAt(m[0]), Annotations: map[string]string{}, Kind: kind, Receiver: goReceiver(s, m[0], args)}
		if defStart, defEnd, ok := goResolveToolDef(s, toolArg); ok {
			consumed[defStart] = true
			goParseToolDef(f, &t, defStart, defEnd)
			t.Line = f.LineAt(defStart)
		}
		if t.Name == "" {
			t.Name = strings.Trim(toolArg.Text(s), "&*")
		}
		if params, from, to, ok := goHandler(f, handlerArg); ok {
			t.Params = params
			f.SetBody(&t, from, to)
		}
		tools = append(tools, t)
	}

	// Tool definitions that were never passed to AddTool in this file: keep the metadata.
	defs := append(goNewToolRe.FindAllStringIndex(f.Skeleton(), -1), goToolLitRe.FindAllStringIndex(f.Skeleton(), -1)...)
	for _, m := range defs {
		start := goDefStart(s, m[0])
		if consumed[start] {
			continue
		}
		end := goDefEnd(s, m)
		if end < 0 {
			continue
		}
		t := source.Tool{Line: f.LineAt(start), Annotations: map[string]string{}}
		switch lit := s[m[0]:m[1]]; {
		case strings.Contains(lit, "Prompt"):
			t.Kind = "prompt"
		case strings.Contains(lit, "Resource"):
			t.Kind = "resource"
		}
		goParseToolDef(f, &t, start, end)
		if t.Name != "" && !hasTool(tools, t.Name) {
			tools = append(tools, t)
		}
	}
	return tools
}

// goReceiver names the server of an AddTool call: "s" in s.AddTool(...), or the first argument
// of mcp.AddTool(server, ...).
func goReceiver(s string, at int, args []source.Segment) string {
	if at > 0 && s[at-1] == '.' {
		i := at - 1
		for i > 0 && (isIdentByte(s[i-1]) || s[i-1] == '.') {
			i--
		}
		if recv := s[i : at-1]; recv != "mcp" && recv != "" {
			return recv
		}
	}
	if len(args) >= 3 { // AddTool(server, tool, handler)
		return strings.TrimSpace(args[0].Text(s))
	}
	return ""
}

var goParamDeclRe = regexp.MustCompile(`^[A-Za-z_]\w*\s+(?:\*|\[\]|\.\.\.)*[A-Za-z_][\w.]*(?:\[[^\]]*\])?$`)

// goDeclaresMethod reports whether the call-looking text at i is a func declaration
// ("func (s *Server) AddTool(...)") rather than a call.
func goDeclaresMethod(s string, i int) bool {
	start := strings.LastIndexByte(s[:i], '\n') + 1
	return strings.HasPrefix(strings.TrimLeft(s[start:i], " \t"), "func ")
}

// goDefStart widens a NewTool/Tool{ match to include a package qualifier and '&'.
func goDefStart(s string, i int) int {
	for i > 0 && (isIdentByte(s[i-1]) || s[i-1] == '.' || s[i-1] == '&') {
		i--
	}
	return i
}

// goDefEnd returns the offset of the closing delimiter of a NewTool( / Tool{ match.
func goDefEnd(s string, m []int) int {
	return source.MatchClose(s, m[1]-1, source.Go)
}

// goResolveToolDef finds the tool definition passed as an AddTool argument: either inline
// or through a variable assigned earlier in the file.
func goResolveToolDef(s string, arg source.Segment) (int, int, bool) {
	text := s[arg.Start:arg.End]
	for _, re := range []*regexp.Regexp{goNewToolRe, goToolLitRe} {
		if loc := re.FindStringIndex(text); loc != nil {
			m := []int{arg.Start + loc[0], arg.Start + loc[1]}
			if end := goDefEnd(s, m); end > 0 {
				return goDefStart(s, m[0]), end, true
			}
		}
	}
	name := strings.Trim(strings.TrimSpace(text), "&*")
	if !isIdent(name) {
		return 0, 0, false
	}
	assign := cachedRegexp(`\b` + regexp.QuoteMeta(name) + `\s*:?=\s*`)
	for _, a := range assign.FindAllStringIndex(s, -1) {
		rest := s[a[1]:min(len(s), a[1]+64)]
		for _, re := range []*regexp.Regexp{goNewToolRe, goToolLitRe} {
			if loc := re.FindStringIndex(rest); loc != nil && !strings.Contains(rest[:loc[0]], "\n") {
				m := []int{a[1] + loc[0], a[1] + loc[1]}
				if end := goDefEnd(s, m); end > 0 {
					return goDefStart(s, m[0]), end, true
				}
			}
		}
	}
	return 0, 0, false
}

func goParseToolDef(f *source.File, t *source.Tool, start, end int) {
	s := f.Code()
	def := s[start : end+1]
	if loc := goNewToolRe.FindStringIndex(def); loc != nil {
		if strings.Contains(def[loc[0]:loc[1]], "NewResource") {
			// NewResource(uri, name, ...): the second argument names the resource.
			if args := source.SplitArgs(def, loc[1], source.MatchClose(def, loc[1]-1, source.Go), source.Go); len(args) > 1 {
				if v, _, ok := source.ParseStringLiteral(def, args[1].Start, source.Go); ok {
					t.Name = v
				}
			}
		} else if v, _, ok := source.ParseStringLiteral(def, loc[1], source.Go); ok {
			t.Name = v
		}
	} else if v, _, ok := keyString(def, "Name", source.Go); ok {
		t.Name = v
	}
	if loc := goWithDescRe.FindStringIndex(def); loc != nil {
		if v, _, ok := source.ParseStringLiteral(def, loc[1], source.Go); ok {
			t.Description, t.DescriptionLine = v, f.LineAt(start+source.SkipSpace(def, loc[1]))
		}
	} else if v, off, ok := keyString(def, "Description", source.Go); ok {
		t.Description, t.DescriptionLine = v, f.LineAt(start+off)
	}
	t.DescriptionDynamic = t.Description == "" && (goWithDescRe.MatchString(def) || hasKey(def, "Description"))
	t.ParamDescriptions = allStrings(def, goParamDescRe, source.Go)
	for k, v := range parseHints(def) {
		t.Annotations[k] = v
	}
}

// goHandler resolves the handler argument (func literal, function name, method value or a
// wrapper call such as mcp.NewTypedToolHandler(fn)) to its parameters and body byte range.
func goHandler(f *source.File, arg source.Segment) ([]string, int, int, bool) {
	s := f.Code()
	start := source.SkipSpace(s, arg.Start)
	text := s[start:arg.End]
	if goFuncLitRe.MatchString(text) {
		return goFuncAt(f, start+strings.IndexByte(text, '('))
	}
	ids := source.Identifiers(text)
	for i := len(ids) - 1; i >= 0; i-- {
		re := cachedRegexp(strings.ReplaceAll(goFuncDeclTmpl, "%s", regexp.QuoteMeta(ids[i])))
		if loc := re.FindStringIndex(s); loc != nil {
			return goFuncAt(f, loc[1]-1)
		}
	}
	return nil, 0, 0, false
}

// goFuncAt parses a function whose parameter list opens at paren.
func goFuncAt(f *source.File, paren int) ([]string, int, int, bool) {
	s := f.Code()
	close := source.MatchClose(s, paren, source.Go)
	if close < 0 {
		return nil, 0, 0, false
	}
	params := goParams(s[paren+1 : close])
	for j := close + 1; j < len(s); j++ {
		switch s[j] {
		case '(', '[':
			if c := source.MatchClose(s, j, source.Go); c > 0 {
				j = c
			}
		case '{':
			bodyClose := source.MatchClose(s, j, source.Go)
			if bodyClose < 0 {
				return nil, 0, 0, false
			}
			return params, j + 1, bodyClose, true
		case ';', '}':
			return nil, 0, 0, false
		}
	}
	return nil, 0, 0, false
}

// goParams returns named parameters, skipping context.Context and blank identifiers.
func goParams(sig string) []string {
	var out []string
	for _, seg := range source.SplitArgs(sig, 0, len(sig), source.Go) {
		fields := strings.Fields(seg.Text(sig))
		if len(fields) == 0 || !isIdent(fields[0]) || fields[0] == "_" {
			continue
		}
		if len(fields) >= 2 && strings.Contains(fields[1], "context.Context") {
			continue
		}
		out = append(out, fields[0])
	}
	return out
}
