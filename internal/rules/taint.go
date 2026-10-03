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
	assignRe = regexp.MustCompile(`^(?:(?:const|let|var)\s+)?([A-Za-z_$][\w$]*(?:\s*,\s*[A-Za-z_$][\w$]*)*|\{[^}]*\}|\[[^\]]*\])\s*(?::\s*[^=]+?)?\s*(:=|\+=|=)\s*([^=>][\s\S]*)$`)
	// d["k"] = v, d[k] = v, self.x = v, this.x = v: the whole container/field becomes tainted.
	memberAssignRe = regexp.MustCompile(`^((?:self|this)\.[A-Za-z_$][\w$]*|[A-Za-z_$][\w$]*)(?:\s*\[[^\]]*\])?\s*(?:\+=|=)\s*([^=>][\s\S]*)$`)
	// xs.append(v), xs.push(v), s.add(v)...: the receiver becomes tainted.
	mutateRe = regexp.MustCompile(`^([A-Za-z_$][\w$]*)\.(?:append|extend|insert|push|unshift|add|update|setdefault|set)\s*\(([\s\S]*)\)$`)
	// with open(p) as f: / async with client.get(u) as r:
	withRe   = regexp.MustCompile(`^(?:async\s+)?with\s+([\s\S]+?)\s*:?$`)
	withAsRe = regexp.MustCompile(`\bas\s+([A-Za-z_]\w*)`)
	forRe    = regexp.MustCompile(`^for\s*\(?\s*(?:(?:const|let|var)\s+)?([\w$,\s\[\]{}]+?)\s+(?:in|of)\s+([\s\S]+?)\)?\s*:?\s*\{?$`)
	goRange  = regexp.MustCompile(`^for\s+([\w,\s]+?)\s*:=\s*range\s+([\s\S]+?)\s*\{?$`)
)

var notVars = map[string]bool{
	"const": true, "let": true, "var": true, "err": true, "_": true, "self": true, "this": true,
	"in": true, "of": true, "range": true,
}

// assign is one parsed assignment: the identifiers written, the expression read, and
// whether it overwrites the targets ("=" / ":=") rather than extending them ("+=", append).
type assign struct {
	ids       []string
	rhs       string
	overwrite bool
}

// assignment splits a statement into assigned identifiers and the right-hand side.
func assignment(stmt string) ([]string, string, bool) {
	a, ok := parseAssign(stmt)
	return a.ids, a.rhs, ok
}

func parseAssign(stmt string) (assign, bool) {
	if m := withRe.FindStringSubmatch(stmt); m != nil {
		var ids []string
		for _, am := range withAsRe.FindAllStringSubmatch(m[1], -1) {
			ids = append(ids, am[1])
		}
		return assign{ids: ids, rhs: m[1]}, len(ids) > 0
	}
	if m := goRange.FindStringSubmatch(stmt); m != nil {
		return assign{ids: assignedIDs(m[1]), rhs: m[2]}, len(assignedIDs(m[1])) > 0
	}
	if m := forRe.FindStringSubmatch(stmt); m != nil {
		return assign{ids: assignedIDs(m[1]), rhs: m[2]}, len(assignedIDs(m[1])) > 0
	}
	if m := assignRe.FindStringSubmatch(stmt); m != nil {
		ids := assignedIDs(m[1])
		return assign{ids: ids, rhs: m[3], overwrite: m[2] != "+="}, len(ids) > 0
	}
	if m := memberAssignRe.FindStringSubmatch(stmt); m != nil {
		return assign{ids: []string{strings.Join(strings.Fields(strings.SplitN(m[1], "[", 2)[0]), "")}, rhs: m[2]}, true
	}
	if m := mutateRe.FindStringSubmatch(stmt); m != nil && !notVars[m[1]] {
		return assign{ids: []string{m[1]}, rhs: m[2]}, true
	}
	return assign{}, false
}

func assignedIDs(lhs string) []string {
	var ids []string
	for _, id := range source.Identifiers(lhs) {
		if !notVars[id] {
			ids = append(ids, id)
		}
	}
	return ids
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
		t.order = append(t.order, id)
	}
	t.has[id] = true
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
	walkTaintWith(f, t, sanitizer, nil, visit)
}

// walkTaintWith is walkTaint with an optional propagate hook: when it returns false for an
// assignment whose right-hand side mentions a tainted value, the target does not become
// tainted. Rules use it when only part of an expression matters (MCPG009: the host of a URL).
func walkTaintWith(f *source.File, t source.Tool, sanitizer *regexp.Regexp, propagate func(rhs string, taint *taintSet) bool, visit func(st source.Stmt, taint *taintSet)) {
	taint := newTaintSet(withoutAll(t.Params, t.FixedParams))
	stmts := f.ToolStatements(t)
	top := 0 // indentation of the handler's top-level statements
	for i, st := range stmts {
		if i == 0 || st.Indent < top {
			top = st.Indent
		}
	}
	for _, st := range stmts {
		visit(st, taint)
		a, ok := parseAssign(st.Text)
		if !ok {
			continue
		}
		if f.Language == source.Go && typedAccessRe.MatchString(a.rhs) {
			continue // req.RequireInt(...) and friends return numbers and booleans
		}
		if taint.find(a.rhs) == "" {
			// A clean overwrite at the top level of the handler dominates what follows, so
			// the target stops being tainted. Inside a branch it might not run: keep the taint.
			if a.overwrite && st.Indent <= top {
				for _, id := range a.ids {
					taint.remove(id)
				}
			}
			continue
		}
		for _, id := range a.ids {
			if (sanitizer != nil && sanitizer.MatchString(a.rhs)) || (propagate != nil && !propagate(a.rhs, taint)) {
				taint.remove(id)
			} else {
				taint.add(id)
			}
		}
	}
}

// typedAccessRe matches mcp-go's typed argument accessors: their results cannot carry a payload.
var typedAccessRe = regexp.MustCompile(`\.(?:Require|Get)(?:Int|Float|Bool)\s*\(`)

func withoutAll(xs, drop []string) []string {
	if len(drop) == 0 {
		return xs
	}
	out := make([]string, 0, len(xs))
	for _, x := range xs {
		if !contains(drop, x) {
			out = append(out, x)
		}
	}
	return out
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
