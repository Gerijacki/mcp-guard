package rules

import (
	"regexp"
	"sort"
	"strings"

	"github.com/Gerijacki/mcp-guard/internal/finding"
	"github.com/Gerijacki/mcp-guard/internal/source"
)

// Helper summaries: a tool often passes its parameters to a function that does the dangerous
// thing (`def read_file(path): return _read(path)`). The taint-based rules therefore analyze,
// besides each tool, one synthetic "view" per (helper, tainted parameters) reached from a tool
// with the helper's parameters tainted, and report at the real sink.
//
// Helpers defined in the same file are resolved by taintBodies. Helpers defined in another
// file go through a Resolver and are returned as CrossCalls, which the scanner runs once every
// file has been analyzed (see CheckCross), so the result does not depend on scheduling.

const maxHelperDepth = 3

var (
	callRe   = regexp.MustCompile(`(?:^|[^\w$.])(?:(?:self|cls|this)\.)?([A-Za-z_$][\w$]*)\s*\(`)
	goCallRe = regexp.MustCompile(`(?:^|[^\w$])(?:[A-Za-z_]\w*\.)?([A-Za-z_]\w*)\s*\(`)
	// A statement that mentions a value together with one of these has probably validated it,
	// so the value is not followed into helpers (precision over recall).
	validationRe = regexp.MustCompile(`(?i)\bnot\s+in\b|\bin\s+[A-Z][A-Z0-9_]{2,}\b|\.includes\(|\.startswith\(|\.startsWith\(|\bstrings\.HasPrefix|\bre\.(?:match|fullmatch|search)\(|\.test\(|\.MatchString\(|isalnum\(|isalpha\(|isdigit\(|isidentifier\(|\bisinstance\(|allow|valid|sanitiz|\bsafe|resolve\(|is_relative_to`)
)

// Resolver finds the single definition of a function that is not defined in the calling file.
// from is the file making the call.
type Resolver func(from *source.File, name string) (*source.File, source.Func, bool)

// ToolChecker is implemented by the rules that can be run on an explicit list of tools
// (the helper views) instead of the tools extracted from the file.
type ToolChecker interface {
	Rule
	CheckTools(f *source.File, tools []source.Tool) []finding.Finding
}

// CrossCall is a call from a tool (or helper view) to a helper defined in another file.
type CrossCall struct {
	Caller      string // display name: the tool, or "tool (via helper)"
	Kind        string
	Line        int
	Annotations map[string]string
	Guards      []string
	Origin      *source.File // file that defines the helper
	Fn          source.Func
	Params      []string // helper parameters that receive tainted values
	Helper      string   // non-empty when the caller is itself a helper view
	Depth       int
}

func (c CrossCall) key() string {
	return c.Origin.Path + "|" + c.Fn.Name + "|" + strings.Join(c.Params, ",")
}

// view turns the call into a synthetic tool whose body is the helper's.
func (c CrossCall) view() source.Tool {
	name := c.Caller + " (via " + c.Fn.Name + ")"
	if c.Helper != "" {
		name = c.Caller + " → " + c.Fn.Name
	}
	return source.Tool{
		Name: name, Kind: c.Kind, Line: c.Line, Annotations: c.Annotations,
		Params: c.Params, Helper: c.Fn.Name, Guards: c.Guards,
		BodyFrom: c.Fn.BodyFrom, BodyTo: c.Fn.BodyTo, BodyStart: c.Fn.BodyStart, BodyEnd: c.Fn.BodyEnd,
	}
}

type helperState struct {
	file    *source.File
	funcs   map[string]source.Func // same-file helpers (unambiguous names)
	resolve Resolver
	seen    map[string]bool // helper views already created in this file
	cross   []CrossCall
}

// localFuncs returns the functions of f that are not MCP handlers and whose name is unique.
func localFuncs(f *source.File) map[string]source.Func {
	handlers := map[[2]int]bool{}
	for _, t := range f.Tools {
		handlers[[2]int{t.BodyFrom, t.BodyTo}] = true
	}
	funcs := map[string]source.Func{}
	ambiguous := map[string]bool{}
	for _, fn := range f.Funcs {
		if handlers[[2]int{fn.BodyFrom, fn.BodyTo}] {
			continue
		}
		if _, dup := funcs[fn.Name]; dup {
			ambiguous[fn.Name] = true
		}
		funcs[fn.Name] = fn
	}
	for name := range ambiguous {
		delete(funcs, name) // two functions with one name: do not guess which one is called
	}
	return funcs
}

// taintBodies is toolBodies plus the same-file helper views. Calls into other files are only
// found when a Resolver is set with SetResolver (see PendingCalls).
func taintBodies(f *source.File) []source.Tool {
	if v, ok := f.Cache["taintBodies"]; ok {
		return v.([]source.Tool)
	}
	out, _ := buildViews(f, nil)
	return out
}

// buildViews computes (and caches) the tools plus helper views of f, and the calls that leave f.
func buildViews(f *source.File, resolve Resolver) ([]source.Tool, []CrossCall) {
	base := toolBodies(f)
	out := base
	var cross []CrossCall
	if len(base) > 0 && (len(f.Funcs) > 0 || resolve != nil) {
		st := &helperState{file: f, funcs: localFuncs(f), resolve: resolve, seen: map[string]bool{}}
		if len(st.funcs) > 0 || resolve != nil {
			out = append([]source.Tool(nil), base...)
			for _, t := range base {
				out = append(out, st.views(t, 0)...)
			}
		}
		cross = st.cross
		if f.Cache == nil {
			f.Cache = map[string]any{}
		}
		f.Cache["localViewKeys"] = st.seen
	}
	if f.Cache == nil {
		f.Cache = map[string]any{}
	}
	f.Cache["taintBodies"] = out
	f.Cache["crossCalls"] = cross
	return out, cross
}

// PendingCalls returns the calls from f's tools into helpers defined in other files, found
// with resolve. It also (re)builds f's own helper views.
func PendingCalls(f *source.File, resolve Resolver) []CrossCall {
	if resolve == nil {
		return nil
	}
	_, cross := buildViews(f, resolve)
	return cross
}

// CheckCross runs the taint rules on helper views of g that were reached from other files,
// and returns the findings plus the calls those helpers make into yet other files.
// done holds the (file, helper, params) keys already analyzed anywhere; it is updated.
func CheckCross(rs []Rule, g *source.File, calls []CrossCall, resolve Resolver, done map[string]bool) ([]finding.Finding, []CrossCall) {
	var views []source.Tool
	var next []CrossCall
	st := &helperState{file: g, funcs: localFuncs(g), resolve: resolve, seen: map[string]bool{}}
	if keys, ok := g.Cache["localViewKeys"].(map[string]bool); ok {
		for k := range keys { // helpers already analyzed through g's own tools
			done[k], st.seen[k] = true, true
		}
	}
	for _, c := range calls {
		if done[c.key()] {
			continue
		}
		done[c.key()] = true
		v := c.view()
		views = append(views, v)
		if c.Depth+1 < maxHelperDepth {
			views = append(views, st.views(v, c.Depth+1)...)
		}
	}
	next = st.cross
	var out []finding.Finding
	for _, r := range rs {
		if tc, ok := r.(ToolChecker); ok && len(views) > 0 {
			out = append(out, tc.CheckTools(g, views)...)
		}
	}
	return out, next
}

// SortCalls orders calls deterministically (by caller, then helper).
func SortCalls(cs []CrossCall) {
	sort.SliceStable(cs, func(i, j int) bool {
		a, b := cs[i], cs[j]
		if a.Caller != b.Caller {
			return a.Caller < b.Caller
		}
		return a.key() < b.key()
	})
}

func (h *helperState) views(t source.Tool, depth int) []source.Tool {
	if depth >= maxHelperDepth {
		return nil
	}
	f := h.file
	re := callRe
	if f.Language == source.Go {
		re = goCallRe
	}
	var views []source.Tool
	walkTaint(f, t, nil, func(st source.Stmt, taint *taintSet) {
		validated := validationRe.MatchString(st.Text)
		for _, m := range re.FindAllStringSubmatchIndex(st.Text, -1) {
			name := st.Text[m[2]:m[3]]
			fn, local := h.funcs[name]
			var origin *source.File
			if !local {
				if h.resolve == nil {
					continue
				}
				var ok bool
				if origin, fn, ok = h.resolve(f, name); !ok {
					continue
				}
			}
			tainted := taintedParams(f, fn, callArgs(st.Text, m[1]-1, f.Language), taint, validated)
			if len(tainted) == 0 {
				continue
			}
			guards := append(append([]string(nil), t.Guards...), f.CodeText(source.Tool{BodyFrom: t.BodyFrom, BodyTo: t.BodyTo}))
			if local {
				c := CrossCall{Caller: t.Name, Kind: t.Kind, Line: t.Line, Annotations: t.Annotations, Guards: guards, Origin: f, Fn: fn, Params: tainted, Helper: t.Helper, Depth: depth}
				if h.seen[c.key()] {
					continue
				}
				h.seen[c.key()] = true
				view := c.view()
				views = append(views, view)
				views = append(views, h.views(view, depth+1)...)
				continue
			}
			h.cross = append(h.cross, CrossCall{Caller: t.Name, Kind: t.Kind, Line: t.Line, Annotations: t.Annotations, Guards: guards, Origin: origin, Fn: fn, Params: tainted, Helper: t.Helper, Depth: depth + 1})
		}
		if validated { // values checked here are not followed any further
			for _, id := range append([]string(nil), taint.order...) {
				if taint.has[id] && source.ContainsIdent(st.Text, id) {
					taint.remove(id)
				}
			}
		}
	})
	return views
}

// taintedParams maps the call arguments to fn's parameters and returns those that receive a
// tainted value.
func taintedParams(f *source.File, fn source.Func, args []string, taint *taintSet, validated bool) []string {
	var tainted []string
	for i, a := range args {
		param := ""
		if name, val, isKw := strings.Cut(a, "="); isKw && f.Language == source.Python && isPlainIdent(strings.TrimSpace(name)) {
			param, a = strings.TrimSpace(name), val
		} else if i < len(fn.Params) {
			param = fn.Params[i]
		}
		if param == "" || !contains(fn.Params, param) || taint.find(a) == "" || validated {
			continue
		}
		tainted = append(tainted, param)
	}
	return tainted
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}

func isPlainIdent(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '_' && (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (i == 0 || c < '0' || c > '9') {
			return false
		}
	}
	return true
}

var (
	_ ToolChecker = fileAccessRule{}
	_ ToolChecker = commandInjectionRule{}
	_ ToolChecker = sqlInjectionRule{}
	_ ToolChecker = ssrfRule{}
	_ ToolChecker = deserializationRule{}
	_ ToolChecker = argInjectionRule{}
)
