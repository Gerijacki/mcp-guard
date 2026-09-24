package rules

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Gerijacki/mcp-guard/internal/extract"
	"github.com/Gerijacki/mcp-guard/internal/source"
)

var fuzzLangs = []source.Language{source.Python, source.TypeScript, source.Go, source.JSON, source.Env, source.YAML}

// FuzzAnalyze feeds arbitrary content through the lexer, the extractors and every
// built-in rule. Scanned repositories are untrusted input: nothing may panic and all
// reported positions must be valid. (Performance is covered by TestPathologicalInputs:
// wall-clock checks inside a fuzz target are flaky.)
//
//	go test ./internal/rules -run '^$' -fuzz FuzzAnalyze -fuzztime 60s
func FuzzAnalyze(f *testing.F) {
	// Seed with every fixture plus a few hand-written edge cases.
	for _, dir := range []string{"../../testdata/rules", "../../testdata/extract", "../../examples"} {
		_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			lang := source.DetectLanguage(p)
			if lang == source.Unknown {
				return nil
			}
			if b, err := os.ReadFile(p); err == nil {
				f.Add(string(b), uint8(indexOf(lang)))
			}
			return nil
		})
	}
	for _, s := range []string{
		"", "(", ")", "{", "\"", "'''", "`${", "@mcp.tool(", "server.tool(\"x\", async ({",
		"s.AddTool(mcp.NewTool(\"x\"", "/* unterminated", "\\", "\"\\u", "\"\\uD800\\u",
		strings.Repeat("(", 5000), strings.Repeat("@mcp.tool()\ndef f(x):\n    os.system(x)\n", 200),
	} {
		for i := range fuzzLangs {
			f.Add(s, uint8(i))
		}
	}

	all := Builtin()
	f.Fuzz(func(t *testing.T, content string, langIdx uint8) {
		if len(content) > 64<<10 {
			return
		}
		lang := fuzzLangs[int(langIdx)%len(fuzzLangs)]
		file := source.NewFile("fuzz", lang, content)
		extract.Extract(file)
		file.Statements(1, len(file.Lines))
		for _, tool := range file.Tools {
			if tool.HasBody() && (tool.BodyFrom < 0 || tool.BodyTo > len(file.Content)) {
				t.Fatalf("tool %q body [%d,%d) outside content of length %d", tool.Name, tool.BodyFrom, tool.BodyTo, len(file.Content))
			}
		}
		for _, r := range all {
			for _, fd := range r.Check(file) {
				if fd.Line < 1 || fd.Line > len(file.Lines) {
					t.Fatalf("%s reported line %d of a %d-line file", fd.RuleID, fd.Line, len(file.Lines))
				}
			}
		}
	})
}

// TestPathologicalInputs guards against super-linear behavior on inputs an attacker
// controls: 1 MiB files (the scanner's size limit) of deep nesting, unterminated
// strings, thousands of tools and very long lines.
func TestPathologicalInputs(t *testing.T) {
	if testing.Short() {
		t.Skip("slow: run without -short (CI runs it separately, without -race)")
	}
	const size = 1 << 20
	inputs := map[string]string{
		"deep nesting":         strings.Repeat("(", size/2) + strings.Repeat(")", size/2),
		"unclosed brackets":    strings.Repeat("f(", size/2),
		"unterminated strings": strings.Repeat("\"'`", size/3),
		"many python tools": strings.Repeat(`@mcp.tool()
def f(x):
    os.system(x)
`, size/40),
		"many ts tools": strings.Repeat(`server.tool("t", "d", {}, async ({ x }) => { exec(x); });
`, size/60),
		"many go tools": strings.Repeat(`s.AddTool(mcp.NewTool("t"), func(ctx context.Context, r mcp.CallToolRequest) (*mcp.CallToolResult, error) { return nil, nil })
`, size/110),
		"one long line":  strings.Repeat("a = b + c; ", size/11),
		"many name keys": strings.Repeat("{ name: \"x\", description: \"y\" }, ", size/35),
		"many assignments": strings.Repeat(`x = x + y
`, size/10),
	}
	all := Builtin()
	for name, content := range inputs {
		for _, lang := range []source.Language{source.Python, source.TypeScript, source.Go} {
			start := time.Now()
			file := source.NewFile("big", lang, content)
			extract.Extract(file)
			for _, r := range all {
				r.Check(file)
			}
			if d := time.Since(start); d > 5*time.Second {
				t.Errorf("%s (%s, %d bytes) took %s", name, lang, len(content), d)
			}
		}
	}
}

func indexOf(lang source.Language) int {
	for i, l := range fuzzLangs {
		if l == lang {
			return i
		}
	}
	return 0
}
