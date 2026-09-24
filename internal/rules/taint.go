package rules

import (
	"regexp"
	"strings"

	"github.com/Gerijacki/mcp-guard/internal/source"
)

// Taint-lite: inside a tool handler, values derived from the tool's parameters are
// "tainted" (model-controlled). We follow simple assignments in statement order:
//
//	cmd = arguments["cmd"]           -> cmd is tainted
//	const { path } = args            -> path is tainted
//	p, err := req.RequireString("p") -> p is tainted
//	safe = safe_path(p)              -> not tainted when the RHS calls a sanitizer
//
// This is intentionally intra-procedural and flow-insensitive to branches; see
// docs/ARCHITECTURE.md for the known limitations.

var (
	assignRe = regexp.MustCompile(`^(?:(?:const|let|var)\s+)?([A-Za-z_$][\w$]*(?:\s*,\s*[A-Za-z_$][\w$]*)*|\{[^}]*\}|\[[^\]]*\])\s*(?::\s*[^=]+?)?\s*(?::=|\+=|=)\s*([^=>][\s\S]*)$`)
	forRe    = regexp.MustCompile(`^for\s*\(?\s*(?:(?:const|let|var)\s+)?([\w$,\s\[\]{}]+?)\s+(?:in|of)\s+([\s\S]+?)\)?\s*:?\s*\{?$`)
	goRange  = regexp.MustCompile(`^for\s+([\w,\s]+?)\s*:=\s*range\s+([\s\S]+?)\s*\{?$`)
)

var notVars = map[string]bool{
	"const": true, "let": true, "var": true, "err": true, "_": true, "self": true, "this": true,
	"in": true, "of": true, "range": true,
}

// assignment splits a statement into assigned identifiers and the right-hand side.
func assignment(stmt string) ([]string, string, bool) {
	for _, re := range []*regexp.Regexp{goRange, forRe, assignRe} {
		m := re.FindStringSubmatch(stmt)
		if m == nil {
			continue
		}
		var ids []string
		for _, id := range source.Identifiers(m[1]) {
			if !notVars[id] {
				ids = append(ids, id)
			}
		}
		return ids, m[2], len(ids) > 0
	}
	return nil, "", false
}

// taintSet is an insertion-ordered set of tainted identifiers.
type taintSet struct {
	order []string
	has   map[string]bool
}

func newTaintSet(params []string) *taintSet {
	t := &taintSet{has: map[string]bool{}}
	for _, p := range params {
		t.add(p)
	}
	return t
}

func (t *taintSet) add(id string) {
	if !t.has[id] {
		t.has[id] = true
		t.order = append(t.order, id)
	}
}

func (t *taintSet) remove(id string) { t.has[id] = false }

// find returns the first tainted identifier mentioned in text, or "".
func (t *taintSet) find(text string) string {
	for _, id := range t.order {
		if t.has[id] && source.ContainsIdent(text, id) {
			return id
		}
	}
	return ""
}

// walkTaint visits the statements of a tool body in order. visit is called for each
// statement with the taint state *before* the statement's own assignment is applied.
// Assignments whose right-hand side matches sanitizer remove the target from the set.
func walkTaint(f *source.File, t source.Tool, sanitizer *regexp.Regexp, visit func(st source.Stmt, taint *taintSet)) {
	taint := newTaintSet(t.Params)
	for _, st := range f.ToolStatements(t) {
		visit(st, taint)
		ids, rhs, ok := assignment(st.Text)
		if !ok {
			continue
		}
		if taint.find(rhs) == "" {
			continue
		}
		for _, id := range ids {
			if sanitizer != nil && sanitizer.MatchString(rhs) {
				taint.remove(id)
			} else {
				taint.add(id)
			}
		}
	}
}

// callArgs returns the argument segments of the call whose "(" is at open in text.
func callArgs(text string, open int, lang source.Language) []string {
	close := source.MatchClose(text, open, lang)
	if close < 0 {
		close = len(text)
	}
	var out []string
	for _, seg := range source.SplitArgs(text, open+1, close, lang) {
		out = append(out, seg.Text(text))
	}
	return out
}

// firstElement returns the first element of a list literal ("[a, b]" -> "a"), or s itself.
func firstElement(s string, lang source.Language) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "[") {
		if close := source.MatchClose(s, 0, lang); close > 0 {
			if segs := source.SplitArgs(s, 1, close, lang); len(segs) > 0 {
				return segs[0].Text(s)
			}
		}
	}
	return s
}

func compileByLang(m map[source.Language]string) map[source.Language]*regexp.Regexp {
	out := make(map[source.Language]*regexp.Regexp, len(m))
	for k, v := range m {
		out[k] = regexp.MustCompile(v)
	}
	return out
}
