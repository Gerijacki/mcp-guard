package rules

import (
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/Gerijacki/mcp-guard/internal/extract"
	"github.com/Gerijacki/mcp-guard/internal/finding"
	"github.com/Gerijacki/mcp-guard/internal/source"
)

// wantCounts pins the exact number of findings per vulnerable fixture so that both
// missed detections and new duplicates show up as test failures.
var wantCounts = map[string]int{
	"MCPG001/vulnerable/files.py":                   2,
	"MCPG001/vulnerable/files.ts":                   1,
	"MCPG001/vulnerable/files.go":                   1,
	"MCPG002/vulnerable/web.py":                     1,
	"MCPG002/vulnerable/web.ts":                     1,
	"MCPG002/vulnerable/web.go":                     1,
	"MCPG003/vulnerable/claude_desktop_config.json": 2,
	"MCPG003/vulnerable/server.py":                  1,
	"MCPG003/vulnerable/server.ts":                  2,
	"MCPG003/vulnerable/server.go":                  1,
	"MCPG003/vulnerable/prod.env":                   1,
	"MCPG004/vulnerable/shell.py":                   3,
	"MCPG004/vulnerable/shell.ts":                   1,
	"MCPG004/vulnerable/shell.go":                   1,
	"MCPG005/vulnerable/db.py":                      2,
	"MCPG005/vulnerable/db.ts":                      1,
	"MCPG005/vulnerable/db.go":                      1,
	"MCPG006/vulnerable/admin.py":                   2,
	"MCPG006/vulnerable/admin.ts":                   1,
	"MCPG006/vulnerable/admin.go":                   1,
	"MCPG007/vulnerable/poisoned.py":                1,
	"MCPG007/vulnerable/poisoned.ts":                1,
	"MCPG007/vulnerable/poisoned.go":                1,
	"MCPG008/vulnerable/http_server.py":             1,
	"MCPG008/vulnerable/http_server.ts":             1,
	"MCPG008/vulnerable/http_server.go":             1,
}

func loadFixture(t *testing.T, path string) *source.File {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	f := source.NewFile(filepath.ToSlash(path), source.DetectLanguage(path), string(b))
	extract.Extract(f)
	return f
}

func describe(fs []finding.Finding) string {
	var sb strings.Builder
	for _, f := range fs {
		sb.WriteString("\n  " + f.File + ":" + strconv.Itoa(f.Line) + " [" + f.Severity.String() + "] " + f.Message)
	}
	return sb.String()
}

func TestBuiltinRulesAgainstFixtures(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "rules")
	for _, r := range Builtin() {
		id := r.Meta().ID
		for _, kind := range []string{"vulnerable", "safe"} {
			dir := filepath.Join(root, id, kind)
			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatalf("%s: %v", id, err)
			}
			if len(entries) == 0 {
				t.Errorf("%s has no %s fixtures", id, kind)
			}
			for _, e := range entries {
				rel := id + "/" + kind + "/" + e.Name()
				t.Run(rel, func(t *testing.T) {
					f := loadFixture(t, filepath.Join(dir, e.Name()))
					got := r.Check(f)
					if kind == "safe" {
						if len(got) != 0 {
							t.Errorf("expected no findings, got %d:%s", len(got), describe(got))
						}
						return
					}
					want, ok := wantCounts[rel]
					if !ok {
						t.Fatalf("no expected count for %s; got %d:%s", rel, len(got), describe(got))
					}
					if len(got) != want {
						t.Errorf("expected %d findings, got %d:%s", want, len(got), describe(got))
					}
					for _, fd := range got {
						if fd.RuleID != id || fd.Line < 1 || fd.Message == "" {
							t.Errorf("malformed finding %+v", fd)
						}
					}
				})
			}
		}
	}
	for rel := range wantCounts {
		if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(rel))); err != nil {
			t.Errorf("expected fixture %s: %v", rel, err)
		}
	}
}

// Known credential formats are tested with runtime-built strings so that no
// realistic-looking token is committed to the repository.
func TestKnownSecretFormats(t *testing.T) {
	cases := map[string]string{
		"Anthropic API key":  "sk-ant-" + "api03-" + strings.Repeat("aB3dE", 18),
		"OpenAI API key":     "sk-" + "proj-" + strings.Repeat("Qw9Er", 8),
		"GitHub token":       "gh" + "p_" + strings.Repeat("a1B2c", 8)[:36],
		"Stripe live key":    "sk" + "_live_" + strings.Repeat("Zx8Cv", 5),
		"Slack token":        "xo" + "xb-" + "1234567890-abcdefghij",
		"Google API key":     "AI" + "za" + strings.Repeat("Sy7Df", 7),
		"Hugging Face token": "hf" + "_" + strings.Repeat("Hg5Jk", 7),
		"Private key":        "-----BEGIN OPENSSH " + "PRIVATE KEY-----",
	}
	r := secretRule{}
	for kind, secret := range cases {
		f := source.NewFile("config.py", source.Python, "value = \""+secret+"\"\n")
		got := r.Check(f)
		if len(got) != 1 || !strings.HasPrefix(got[0].Message, kind) {
			t.Errorf("%s: got %s", kind, describe(got))
			continue
		}
		if len(secret) > 20 && strings.Contains(got[0].Snippet, secret) {
			t.Errorf("%s: snippet is not redacted: %s", kind, got[0].Snippet)
		}
	}
}

func TestSplitWords(t *testing.T) {
	cases := map[string]string{
		"delete_file":       "delete file",
		"terminateInstance": "terminate instance",
		"HTTPRequest":       "http request",
		"kill-process.v2":   "kill process v2",
		"runSQLQuery":       "run sql query",
	}
	for in, want := range cases {
		if got := strings.Join(splitWords(in), " "); got != want {
			t.Errorf("splitWords(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCustomRule(t *testing.T) {
	r, err := CompileCustom(CustomSpec{
		ID: "ACME001", Severity: "high", Scope: "tool-body", Pattern: `\brequests\.delete\s*\(`,
		RequiresTaintedInput: true, Message: "Tool {tool} sends DELETE with {param}",
	})
	if err != nil {
		t.Fatal(err)
	}
	src := "from mcp.server.fastmcp import FastMCP\nmcp = FastMCP('x')\n\n@mcp.tool()\ndef rm(url: str) -> str:\n    \"\"\"Remove.\"\"\"\n    requests.delete(url)\n    requests.delete('https://fixed.example')\n    return 'ok'\n"
	f := source.NewFile("x.py", source.Python, src)
	extract.Extract(f)
	got := r.Check(f)
	if len(got) != 1 || got[0].Line != 7 || got[0].Message != "Tool rm sends DELETE with url" || got[0].Severity != finding.High {
		t.Fatalf("got %s", describe(got))
	}
	for _, bad := range []CustomSpec{
		{ID: "MCPG999", Pattern: "x"},
		{ID: "lower", Pattern: "x"},
		{ID: "ACME002", Pattern: "("},
		{ID: "ACME003", Pattern: "x", Scope: "file", RequiresTaintedInput: true},
		{ID: "ACME004", Pattern: "x", Languages: []string{"cobol"}},
	} {
		if _, err := CompileCustom(bad); err == nil {
			t.Errorf("CompileCustom(%+v) should fail", bad)
		}
	}
}

// Findings must point at the sink statement, not at the tool declaration, even when the
// handler starts on the same line as server.tool(...).
func TestFindingLines(t *testing.T) {
	cases := []struct {
		rule Rule
		path string
		want []int
	}{
		{commandInjectionRule{}, "MCPG004/vulnerable/shell.ts", []int{10}},
		{commandInjectionRule{}, "MCPG004/vulnerable/shell.py", []int{12, 24, 30}},
		{sqlInjectionRule{}, "MCPG005/vulnerable/db.ts", []int{9}},
		{fileAccessRule{}, "MCPG001/vulnerable/files.go", []int{21}},
		{passthroughRule{}, "MCPG002/vulnerable/web.py", []int{10}},
	}
	for _, c := range cases {
		f := loadFixture(t, filepath.Join("..", "..", "testdata", "rules", filepath.FromSlash(c.path)))
		var got []int
		for _, fd := range c.rule.Check(f) {
			got = append(got, fd.Line)
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: lines %v, want %v", c.path, got, c.want)
		}
	}
}

func TestSnippetEscapesControlAndInvisibleChars(t *testing.T) {
	got := snippet("  x = \"\x1b[2Jcleared\u200b\u202Eevil\U000E0041\"  ")
	want := `x = "\u001B[2Jcleared\u200B\u202Eevil\U000E0041"`
	if got != want {
		t.Errorf("snippet = %q, want %q", got, want)
	}
}

func TestSecretFiltersAndRedaction(t *testing.T) {
	r := secretRule{}
	check := func(path, src string) []finding.Finding {
		f := source.NewFile(path, source.DetectLanguage(path), src)
		extract.Extract(f)
		return r.Check(f)
	}
	// Only the password itself is redacted, not other occurrences of the same text.
	got := check("db.py", `DSN = "postgresql://svc:Kq8Zp3Lm9Xw2@db.prod.internal:5432/app"`+"\n")
	if len(got) != 1 || !strings.Contains(got[0].Snippet, "postgresql://svc:") || strings.Contains(got[0].Snippet, "Kq8Zp3Lm9Xw2") {
		t.Errorf("redaction: %s", describe(got))
	}
	for name, src := range map[string]string{
		"localhost dsn":   `DSN = "postgresql://svc:Kq8Zp3Lm9Xw2@localhost:5432/app"`,
		"default creds":   `DSN = "postgresql://postgres:postgres@db.prod.internal/app"`,
		"self-describing": `DEMO_CLIENT_SECRET = "demo-client-secret-42"`,
		"sequential":      `expected_token = "0123456789abcdefABCDEF"`,
		"short":           `progress_token = "tok-12345"`,
	} {
		if got := check("x.py", src+"\n"); len(got) != 0 {
			t.Errorf("%s: unexpected finding %s", name, describe(got))
		}
	}
	if got := check(".env.example", "LLM_API_KEY=gsk_Kq8Zp3Lm9Xw2Vb7N\n"); len(got) != 0 {
		t.Errorf("template env file: %s", describe(got))
	}
}
