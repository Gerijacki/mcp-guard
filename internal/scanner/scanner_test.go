package scanner

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Gerijacki/mcp-guard/internal/finding"
	"github.com/Gerijacki/mcp-guard/internal/rules"
	"github.com/Gerijacki/mcp-guard/internal/source"
)

func TestMatchGlob(t *testing.T) {
	cases := []struct {
		pattern, path string
		want          bool
	}{
		{"tests", "tests/a.py", true},
		{"tests", "src/tests/a.py", true},
		{"tests/", "tests/a.py", true},
		{"*.test.ts", "src/x.test.ts", true},
		{"*.test.ts", "src/x.ts", false},
		{"src/*.py", "src/a.py", true},
		{"src/*.py", "src/sub/a.py", false},
		{"src/**/*.py", "src/sub/deep/a.py", true},
		{"src/**/*.py", "src/a.py", true},
		{"**/fixtures/**", "a/fixtures/b/c.json", true},
		{"examples", "docs/a.md", false},
		{"./examples", "examples/x.py", true},
	}
	for _, c := range cases {
		if got := matchGlob(c.pattern, c.path); got != c.want {
			t.Errorf("matchGlob(%q, %q) = %v, want %v", c.pattern, c.path, got, c.want)
		}
	}
}

func write(t *testing.T, dir, name, content string) {
	t.Helper()
	p := filepath.Join(dir, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

const vulnerableTool = `from mcp.server.fastmcp import FastMCP
import os

mcp = FastMCP("x")


@mcp.tool()
def run(cmd: str) -> str:
    """Run a shell command on the host."""
    return os.popen(cmd).read()
`

func TestScanSuppressionIgnoreAndSkips(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "server.py", vulnerableTool)
	write(t, dir, "suppressed.py", `from mcp.server.fastmcp import FastMCP
import os

mcp = FastMCP("x")


@mcp.tool()
def run(cmd: str) -> str:
    """Run a shell command on the host."""
    # mcp-guard:ignore MCPG004 -- runs in a disposable sandbox
    return os.popen(cmd).read()
`)
	write(t, dir, "wrong_id.py", `from mcp.server.fastmcp import FastMCP
import os

mcp = FastMCP("x")


@mcp.tool()
def run(cmd: str) -> str:
    """Run a shell command on the host."""
    return os.popen(cmd).read()  # mcp-guard:ignore MCPG001
`)
	write(t, dir, "node_modules/pkg/index.py", vulnerableTool)
	write(t, dir, "tests/test_server.py", vulnerableTool)
	write(t, dir, "binary.py", "\x00\x01"+vulnerableTool)

	res, err := Scan(Options{Root: dir, Rules: rules.Builtin(), Ignore: []string{"tests"}})
	if err != nil {
		t.Fatal(err)
	}
	var files []string
	for _, f := range res.Findings {
		if f.RuleID == "MCPG004" {
			files = append(files, filepath.Base(f.File))
		}
	}
	if len(files) != 2 || files[0] != "server.py" || files[1] != "wrong_id.py" {
		t.Errorf("MCPG004 findings in %v, want [server.py wrong_id.py]", files)
	}
	if res.FilesScanned != 3 {
		t.Errorf("FilesScanned = %d, want 3 (node_modules, ignored and binary files skipped)", res.FilesScanned)
	}
	for _, f := range res.Findings {
		if f.Fingerprint == "" {
			t.Errorf("finding without fingerprint: %+v", f)
		}
	}
}

func TestScanOverridesAndDisable(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "server.py", vulnerableTool)
	res, err := Scan(Options{
		Root:              filepath.Join(dir, "server.py"),
		Rules:             rules.Builtin(),
		Disabled:          map[string]bool{"MCPG006": true},
		SeverityOverrides: map[string]finding.Severity{"MCPG004": finding.Low},
		MinSeverity:       finding.Low,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 || res.Findings[0].RuleID != "MCPG004" || res.Findings[0].Severity != finding.Low {
		t.Fatalf("findings = %+v", res.Findings)
	}
	for _, m := range res.Rules {
		if m.ID == "MCPG006" {
			t.Error("disabled rule reported as active")
		}
	}
}

type slowRule struct{}

func (slowRule) Meta() rules.Meta { return rules.Meta{ID: "SLOW001", Name: "slow"} }

func (slowRule) Check(*source.File) []finding.Finding {
	time.Sleep(2 * time.Second)
	return nil
}

func TestScanFileTimeout(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "server.py", vulnerableTool)
	start := time.Now()
	res, err := Scan(Options{Root: dir, Rules: []rules.Rule{slowRule{}}, FileTimeout: 50 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if time.Since(start) > time.Second {
		t.Errorf("scan did not honor the file timeout (%s)", time.Since(start))
	}
	if len(res.Warnings) != 1 || res.FilesScanned != 0 {
		t.Errorf("warnings = %v, files = %d", res.Warnings, res.FilesScanned)
	}
}
