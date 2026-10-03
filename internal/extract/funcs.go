package extract

import (
	"regexp"
	"strings"

	"github.com/Gerijacki/mcp-guard/internal/source"
)

// maxFuncs bounds the work spent on generated files with thousands of functions.
const maxFuncs = 4000

var (
	tsFuncAnyRe   = regexp.MustCompile(`(?m)(?:^|[^\w$.])(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s*\*?\s*([A-Za-z_$][\w$]*)\s*(?:<[^>(]*>)?\s*\(`)
	tsConstFuncRe = regexp.MustCompile(`(?m)(?:^|[^\w$.])(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=\n]+)?=\s*`)
	// What may follow "const name =" for the value to be a function: params then "=>".
	tsArrowHeadRe = regexp.MustCompile(`^(?:async\s+)?(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*(?::\s*[^=]{0,80})?=>`)
	goFuncAnyRe   = regexp.MustCompile(`(?m)^func\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*\(`)
)

// extractFuncs fills f.Funcs with the functions and methods defined in the file, whether or
// not they are MCP handlers.
func extractFuncs(f *source.File) {
	switch f.Language {
	case source.Python:
		pyFuncs(f)
	case source.TypeScript:
		tsFuncs(f)
	case source.Go:
		goFuncs(f)
	}
}

func addFunc(f *source.File, name string, params []string, from, to, line int) {
	fn := source.Func{Name: name, Params: params, Line: line}
	if to <= from {
		return
	}
	t := source.Tool{}
	f.SetBody(&t, from, to)
	if !t.HasBody() {
		return
	}
	fn.BodyFrom, fn.BodyTo, fn.BodyStart, fn.BodyEnd = t.BodyFrom, t.BodyTo, t.BodyStart, t.BodyEnd
	f.Funcs = append(f.Funcs, fn)
}

func pyFuncs(f *source.File) {
	s := f.Code()
	for _, loc := range pyDefRe.FindAllStringSubmatchIndex(s, maxFuncs) {
		if fn, ok := pyFunction(f, loc); ok {
			addFunc(f, fn.name, fn.params, fn.bodyFrom, fn.bodyTo, fn.line)
		}
	}
}

func tsFuncs(f *source.File) {
	s := f.Code()
	n := 0
	for _, m := range tsFuncAnyRe.FindAllStringSubmatchIndex(s, maxFuncs) {
		paren := m[1] - 1
		if params, from, to, ok := tsHandler(f, paren, len(s)); ok {
			addFunc(f, s[m[2]:m[3]], params, from, to, f.LineAt(m[2]))
			n++
		}
	}
	for _, m := range tsConstFuncRe.FindAllStringSubmatchIndex(s, maxFuncs) {
		if n >= maxFuncs {
			return
		}
		head := s[m[1]:min(len(s), m[1]+240)]
		if !tsArrowHeadRe.MatchString(head) {
			continue
		}
		if params, from, to, ok := tsHandler(f, m[1], len(s)); ok {
			addFunc(f, s[m[2]:m[3]], params, from, to, f.LineAt(m[2]))
			n++
		}
	}
}

func goFuncs(f *source.File) {
	s := f.Code()
	for _, m := range goFuncAnyRe.FindAllStringSubmatchIndex(s, maxFuncs) {
		name := s[m[2]:m[3]]
		if name == "main" || name == "init" || strings.HasPrefix(name, "Test") {
			continue
		}
		if params, from, to, ok := goFuncAt(f, m[1]-1); ok {
			addFunc(f, name, params, from, to, f.LineAt(m[2]))
		}
	}
}
