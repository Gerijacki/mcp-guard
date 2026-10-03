package scanner

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Gerijacki/mcp-guard/internal/finding"
	"github.com/Gerijacki/mcp-guard/internal/rules"
	"github.com/Gerijacki/mcp-guard/internal/source"
)

func vulnWith(comment string, same bool) string {
	call := "    return os.popen(cmd).read()"
	above := ""
	if same {
		call += "  " + comment
	} else if comment != "" {
		above = "    " + comment + "\n"
	}
	return "from mcp.server.fastmcp import FastMCP\nimport os\n\nmcp = FastMCP(\"x\")\n\n\n@mcp.tool()\ndef run(cmd: str) -> str:\n    \"\"\"Run a shell command.\"\"\"\n" + above + call + "\n"
}

func scanOne(t *testing.T, content string, o Options) *Result {
	t.Helper()
	dir := t.TempDir()
	write(t, dir, "server.py", content)
	o.Root, o.Rules = dir, rules.Builtin()
	res, err := Scan(o)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func count(res *Result, id string) int {
	n := 0
	for _, f := range res.Findings {
		if f.RuleID == id {
			n++
		}
	}
	return n
}

func TestSuppressionForms(t *testing.T) {
	cases := []struct {
		name    string
		content string
		hidden  bool
	}{
		{"bare ignore hides every rule", vulnWith("# mcp-guard:ignore", true), true},
		{"several ids", vulnWith("# mcp-guard:ignore MCPG001, MCPG004", true), true},
		{"wrong id", vulnWith("# mcp-guard:ignore MCPG001", true), false},
		{"line above", vulnWith("# mcp-guard:ignore MCPG004", false), true},
		{"next-line", vulnWith("# mcp-guard:ignore-next-line MCPG004", false), true},
		{"inside a string literal is not a suppression", strings.Replace(vulnWith("", true), "os.popen(cmd)", "os.popen(cmd + \" mcp-guard:ignore\")", 1), false},
		{"no comment", vulnWith("", true), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := scanOne(t, c.content, Options{})
			if got := count(res, "MCPG004") == 0; got != c.hidden {
				t.Errorf("hidden = %v, want %v (findings: %+v)", got, c.hidden, res.Findings)
			}
		})
	}
}

func TestIgnoreFileAndReasons(t *testing.T) {
	file := "# mcp-guard:ignore-file MCPG004 -- demo server\n" + vulnWith("", true)
	if res := scanOne(t, file, Options{}); count(res, "MCPG004") != 0 {
		t.Errorf("ignore-file did not suppress: %+v", res.Findings)
	}

	noReason := vulnWith("# mcp-guard:ignore MCPG004", true)
	res := scanOne(t, noReason, Options{RequireIgnoreReason: true})
	if count(res, "MCPG004") != 1 || len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "add a reason") {
		t.Errorf("reason required: findings=%d warnings=%v", count(res, "MCPG004"), res.Warnings)
	}
	withReason := vulnWith("# mcp-guard:ignore MCPG004 -- sandboxed", true)
	if res := scanOne(t, withReason, Options{RequireIgnoreReason: true}); count(res, "MCPG004") != 0 {
		t.Errorf("reason given but finding kept: %+v", res.Findings)
	}
	freeText := vulnWith("# mcp-guard:ignore MCPG004 vetted allowlist", true)
	if res := scanOne(t, freeText, Options{RequireIgnoreReason: true}); count(res, "MCPG004") != 0 {
		t.Errorf("free-text reason not accepted: %+v", res.Findings)
	}
}

func TestUnusedIgnoreWarning(t *testing.T) {
	src := "from mcp.server.fastmcp import FastMCP\nmcp = FastMCP(\"x\")\n# mcp-guard:ignore MCPG004\nx = 1\n"
	if res := scanOne(t, src, Options{}); len(res.Warnings) != 0 {
		t.Errorf("unused ignores must be silent by default: %v", res.Warnings)
	}
	res := scanOne(t, src, Options{WarnUnusedIgnores: true})
	if len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "unused mcp-guard:ignore") {
		t.Errorf("warnings = %v", res.Warnings)
	}
}

type panicRule struct{}

func (panicRule) Meta() rules.Meta { return rules.Meta{ID: "TEST001", Name: "boom"} }
func (panicRule) Check(*source.File) []finding.Finding {
	var f *source.File
	_ = f.Path // nil pointer dereference
	return nil
}

func TestPanicInRuleIsReportedNotFatal(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "a.py", "x = 1\n")
	write(t, dir, "b.py", vulnerableTool)
	res, err := Scan(Options{Root: dir, Rules: append(rules.Builtin(), panicRule{}), Workers: 2})
	if err != nil {
		t.Fatal(err)
	}
	if res.Skipped.Failed != 2 || len(res.Warnings) != 2 || !strings.Contains(res.Warnings[0], "internal error") {
		t.Errorf("skipped=%+v warnings=%v", res.Skipped, res.Warnings)
	}
	if res.FilesScanned != 0 {
		t.Errorf("FilesScanned = %d", res.FilesScanned)
	}
}

func TestSkipCountsAndOnly(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "ok.py", vulnerableTool)
	write(t, dir, "other.py", vulnerableTool)
	write(t, dir, "bin.py", "\x00\x01\x02")
	write(t, dir, "big.py", strings.Repeat("x = 1\n", 40))
	res, err := Scan(Options{Root: dir, Rules: rules.Builtin(), MaxFileSize: 100})
	if err != nil {
		t.Fatal(err)
	}
	// ok.py, other.py and big.py exceed 100 bytes; bin.py is small and binary.
	if res.Skipped.Binary != 1 || res.Skipped.TooLarge != 3 || res.Skipped.Total() != 4 || res.FilesScanned != 0 {
		t.Errorf("skipped = %+v, scanned = %d", res.Skipped, res.FilesScanned)
	}
	res, err = Scan(Options{Root: dir, Rules: rules.Builtin(), Only: map[string]bool{CanonicalPath(filepath.Join(dir, "ok.py")): true}})
	if err != nil {
		t.Fatal(err)
	}
	if res.FilesScanned != 1 || !strings.HasSuffix(res.Findings[0].File, "ok.py") {
		t.Errorf("Only: scanned %d files, findings %+v", res.FilesScanned, res.Findings)
	}
}

func TestPathRulesDisableByGlob(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "src/server.py", vulnerableTool)
	write(t, dir, "scripts/server.py", vulnerableTool)
	res, err := Scan(Options{Root: dir, Rules: rules.Builtin(), PathRules: []PathRule{{Glob: "scripts/**", Disabled: map[string]bool{"MCPG004": true}}}})
	if err != nil {
		t.Fatal(err)
	}
	if count(res, "MCPG004") != 1 || !strings.Contains(res.Findings[0].File, "src") {
		t.Errorf("path override: %+v", res.Findings)
	}
}

func TestDuplicateFindingsGetDistinctFingerprints(t *testing.T) {
	src := "from mcp.server.fastmcp import FastMCP\nimport os\nmcp = FastMCP(\"x\")\n\n@mcp.tool()\ndef run(a: str, b: str) -> str:\n    \"\"\"Run.\"\"\"\n    os.system(a)\n    os.system(a)\n    return \"\"\n"
	res := scanOne(t, src, Options{})
	fps := map[string]bool{}
	for _, f := range res.Findings {
		if f.RuleID == "MCPG004" {
			fps[f.Fingerprint] = true
		}
	}
	if count(res, "MCPG004") != 2 || len(fps) != 2 {
		t.Errorf("findings=%d distinct fingerprints=%d (%s)", count(res, "MCPG004"), len(fps), fmt.Sprint(res.Findings))
	}
}

func TestUnreadableEntriesWarn(t *testing.T) {
	res := scanOne(t, "x = 1\n", Options{})
	if res.Skipped.Total() != 0 || len(res.Warnings) != 0 {
		t.Errorf("clean scan reported skips: %+v %v", res.Skipped, res.Warnings)
	}
}

func TestDuplicateToolNamesInOneFile(t *testing.T) {
	tool := func(name string) string {
		return "@mcp.tool()\ndef " + name + "(a: int) -> int:\n    \"\"\"Add.\"\"\"\n    return a\n\n\n"
	}
	head := "from mcp.server.fastmcp import FastMCP\nmcp = FastMCP('x')\n\n\n"
	dir := t.TempDir()
	write(t, dir, "dup.py", head+tool("add")+tool("add"))
	// The same name in two files is two different servers (examples, tests): not reported.
	write(t, dir, "a.py", head+tool("echo"))
	write(t, dir, "b.py", head+tool("echo"))
	res := scanDir(t, dir, Options{})
	var dups []string
	for _, f := range res.Findings {
		if f.RuleID == "MCPG017" {
			dups = append(dups, f.File+": "+f.Message)
		}
	}
	if len(dups) != 1 || !strings.Contains(dups[0], "dup.py") || !strings.Contains(dups[0], "registered twice") {
		t.Fatalf("MCPG017 = %v", dups)
	}
	write(t, dir, "dup.py", "# mcp-guard:ignore-file MCPG017 -- alternatives selected by config\n"+head+tool("add")+tool("add"))
	if res := scanDir(t, dir, Options{}); len(findingsIn(res, "MCPG017", ".py")) != 0 {
		t.Errorf("suppressed duplicate still reported: %+v", res.Findings)
	}
}

func TestStorybookAndTestFilesAreSkipped(t *testing.T) {
	dir := t.TempDir()
	token := `export const demo = { accessToken: "Zq8vN2kL5xW9pR3tY7uB1mC4" };` + "\n"
	write(t, dir, "Button.stories.tsx", token)
	write(t, dir, "Button.test.tsx", token)
	write(t, dir, "real.ts", token)
	res := scanDir(t, dir, Options{})
	var files []string
	for _, f := range res.Findings {
		files = append(files, filepath.Base(f.File))
	}
	if len(files) != 1 || files[0] != "real.ts" {
		t.Errorf("findings in %v, want only real.ts", files)
	}
	if res := scanDir(t, dir, Options{IncludeTests: true}); res.FilesScanned != 3 {
		t.Errorf("--include-tests should bring the demo files back, scanned %d", res.FilesScanned)
	}
}
