package rules

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/Gerijacki/mcp-guard/internal/extract"
	"github.com/Gerijacki/mcp-guard/internal/source"
)

// Metamorphic tests: behavior-preserving edits must not change what is reported. Findings are
// compared as (rule, severity, tool) multisets, ignoring line numbers and message text.

func signature(f *source.File) []string {
	extract.Extract(f)
	var out []string
	for _, r := range Builtin() {
		for _, fd := range r.Check(f) {
			out = append(out, fd.RuleID+"|"+fd.Severity.String()+"|"+fd.Tool)
		}
	}
	sort.Strings(out)
	return out
}

func fixtures(t *testing.T) map[string]string {
	t.Helper()
	root := filepath.Join("..", "..", "testdata", "rules")
	out := map[string]string{}
	filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		if source.DetectLanguage(p) == source.Unknown || !source.DetectLanguage(p).IsCode() {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		out[filepath.ToSlash(p)] = string(b)
		return nil
	})
	if len(out) < 40 {
		t.Fatalf("only %d code fixtures found", len(out))
	}
	return out
}

func commentFor(lang source.Language) string {
	if lang == source.Python {
		return "# unrelated comment\n"
	}
	return "// unrelated comment\n"
}

func TestMetamorphicNoiseDoesNotChangeFindings(t *testing.T) {
	transforms := map[string]func(src string, lang source.Language) string{
		"leading comments and blank lines": func(s string, l source.Language) string {
			return commentFor(l) + "\n\n" + commentFor(l) + s
		},
		"trailing blank lines and comment": func(s string, l source.Language) string {
			return s + "\n\n" + commentFor(l)
		},
		"CRLF line endings": func(s string, l source.Language) string {
			return strings.ReplaceAll(s, "\n", "\r\n")
		},
		"trailing whitespace": func(s string, l source.Language) string {
			return strings.ReplaceAll(s, "\n", "  \n")
		},
	}
	for path, src := range fixtures(t) {
		lang := source.DetectLanguage(path)
		want := signature(source.NewFile(path, lang, src))
		for name, tr := range transforms {
			got := signature(source.NewFile(path, lang, tr(src, lang)))
			if strings.Join(got, ",") != strings.Join(want, ",") {
				t.Errorf("%s with %s:\n  before %v\n  after  %v", path, name, want, got)
			}
		}
	}
}

// Renaming a tool's parameters everywhere in the file must not change what is reported.
func TestMetamorphicParameterRenaming(t *testing.T) {
	skip := map[string]bool{"self": true, "ctx": true, "context": true, "req": true, "request": true}
	for path, src := range fixtures(t) {
		lang := source.DetectLanguage(path)
		f := source.NewFile(path, lang, src)
		want := signature(f)
		renamed := src
		seen := map[string]bool{}
		for _, tool := range f.Tools {
			for _, p := range tool.Params {
				if skip[p] || seen[p] || len(p) < 3 {
					continue
				}
				seen[p] = true
				renamed = regexp.MustCompile(`\b`+regexp.QuoteMeta(p)+`\b`).ReplaceAllString(renamed, p+"_renamed")
			}
		}
		if renamed == src {
			continue
		}
		got := signature(source.NewFile(path, lang, renamed))
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("%s after renaming %v:\n  before %v\n  after  %v", path, keys(seen), want, got)
		}
	}
}

func keys(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Running a rule twice on the same file gives the same answer (no hidden state, and the
// caches added for performance do not leak between runs).
func TestRulesAreDeterministicAndIdempotent(t *testing.T) {
	for path, src := range fixtures(t) {
		f := source.NewFile(path, source.DetectLanguage(path), src)
		extract.Extract(f)
		for _, r := range Builtin() {
			a, b := describe(r.Check(f)), describe(r.Check(f))
			if a != b {
				t.Errorf("%s %s is not idempotent:\n%s\n%s", path, r.Meta().ID, a, b)
			}
		}
	}
}

// A safe fixture stays safe (for the rule it is a near-miss of) when the file gets a header
// comment and extra blank lines: guards must not depend on layout.
func TestSafeFixturesStaySafeUnderLayoutChanges(t *testing.T) {
	ruleOf := regexp.MustCompile(`/(MCPG\d+)/safe/`)
	for path, src := range fixtures(t) {
		m := ruleOf.FindStringSubmatch(path)
		if m == nil {
			continue
		}
		lang := source.DetectLanguage(path)
		f := source.NewFile(path, lang, commentFor(lang)+"\n"+src+"\n")
		extract.Extract(f)
		for _, r := range Builtin() {
			if r.Meta().ID != m[1] {
				continue
			}
			if got := r.Check(f); len(got) != 0 {
				t.Errorf("%s: findings appeared on a safe fixture:%s", path, describe(got))
			}
		}
	}
}
