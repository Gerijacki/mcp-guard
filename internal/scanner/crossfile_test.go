package scanner

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/Gerijacki/mcp-guard/internal/rules"
)

const pyTool = `from mcp.server.fastmcp import FastMCP

from utils import read_any

mcp = FastMCP("x")


@mcp.tool()
def read_note(path: str) -> str:
    """Read a note."""
    return read_any(path)
`

const pyHelper = `def read_any(p):
    with open(p) as fh:
        return fh.read()
`

func findingsIn(res *Result, rule, file string) []string {
	var out []string
	for _, f := range res.Findings {
		if f.RuleID == rule && strings.HasSuffix(f.File, file) {
			out = append(out, fmt.Sprintf("%d %s", f.Line, f.Tool))
		}
	}
	return out
}

func scanDir(t *testing.T, dir string, o Options) *Result {
	t.Helper()
	o.Root, o.Rules = dir, rules.Builtin()
	res, err := Scan(o)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestCrossFileHelperPython(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "server.py", pyTool)
	write(t, dir, "utils.py", pyHelper)
	res := scanDir(t, dir, Options{})
	got := findingsIn(res, "MCPG001", "utils.py")
	if !reflect.DeepEqual(got, []string{"2 read_note (via read_any)"}) {
		t.Fatalf("findings = %v (all: %+v)", got, res.Findings)
	}
	if res := scanDir(t, dir, Options{NoCrossFile: true}); len(findingsIn(res, "MCPG001", "utils.py")) != 0 {
		t.Errorf("NoCrossFile still followed the helper")
	}
}

func TestCrossFileNeedsUniqueDefinitionAndImportEvidence(t *testing.T) {
	// Two definitions of the same name: the call cannot be attributed.
	dir := t.TempDir()
	write(t, dir, "server.py", pyTool)
	write(t, dir, "utils.py", pyHelper)
	write(t, dir, "other/helpers.py", pyHelper)
	if res := scanDir(t, dir, Options{}); len(findingsIn(res, "MCPG001", ".py")) != 0 {
		t.Errorf("ambiguous helper was followed: %+v", res.Findings)
	}

	// A single definition in a module the caller never mentions.
	dir = t.TempDir()
	write(t, dir, "server.py", strings.Replace(pyTool, "from utils import read_any\n", "", 1)+"\ndef read_any(p):\n    return p\n")
	write(t, dir, "elsewhere.py", "def other(p):\n    return open(p).read()\n")
	if res := scanDir(t, dir, Options{}); len(findingsIn(res, "MCPG001", "elsewhere.py")) != 0 {
		t.Errorf("unrelated module was followed: %+v", res.Findings)
	}
}

func TestCrossFileGuardInCallerAppliesToHelper(t *testing.T) {
	dir := t.TempDir()
	guarded := strings.Replace(pyTool, "    return read_any(path)", "    if not path.startswith('/srv/'):\n        raise ValueError(path)\n    return read_any(path)", 1)
	write(t, dir, "server.py", guarded)
	write(t, dir, "utils.py", pyHelper)
	if res := scanDir(t, dir, Options{}); len(findingsIn(res, "MCPG001", "utils.py")) != 0 {
		t.Errorf("a validated argument was followed into the helper: %+v", res.Findings)
	}
}

func TestCrossFileChainAcrossThreeFiles(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "server.py", strings.ReplaceAll(pyTool, "utils", "middle")+"")
	write(t, dir, "middle.py", "from deep import dig\n\n\ndef read_any(p):\n    return dig(p)\n")
	write(t, dir, "deep.py", "def dig(q):\n    return open(q).read()\n")
	res := scanDir(t, dir, Options{})
	got := findingsIn(res, "MCPG001", "deep.py")
	if len(got) != 1 || !strings.Contains(got[0], "read_note (via read_any) → dig") {
		t.Fatalf("chain findings = %v (all: %+v)", got, res.Findings)
	}
}

func TestCrossFileGoSamePackage(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "main.go", `package main

import (
	"context"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func main() {
	s := server.NewMCPServer("x", "1.0.0")
	s.AddTool(mcp.NewTool("run", mcp.WithDescription("Run a command"), mcp.WithString("cmd", mcp.Required())), run)
}

func run(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	cmd, err := req.RequireString("cmd")
	if err != nil {
		return nil, err
	}
	out, err := execute(cmd)
	if err != nil {
		return nil, err
	}
	return mcp.NewToolResultText(out), nil
}
`)
	write(t, dir, "exec.go", `package main

import "os/exec"

func execute(command string) (string, error) {
	out, err := exec.Command("sh", "-c", command).CombinedOutput()
	return string(out), err
}
`)
	res := scanDir(t, dir, Options{})
	if got := findingsIn(res, "MCPG004", "exec.go"); len(got) != 1 || !strings.Contains(got[0], "run (via execute)") {
		t.Fatalf("go cross-file findings = %v (all: %+v)", got, res.Findings)
	}
}

func TestCrossFileResultsDoNotDependOnWorkers(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 6; i++ {
		write(t, dir, fmt.Sprintf("srv%d.py", i), strings.ReplaceAll(strings.ReplaceAll(pyTool, "read_note", fmt.Sprintf("read_note%d", i)), "utils", "shared"))
	}
	write(t, dir, "shared.py", pyHelper)
	var first []string
	for _, workers := range []int{1, 2, 8, 8, 3} {
		res := scanDir(t, dir, Options{Workers: workers})
		var got []string
		for _, f := range res.Findings {
			got = append(got, f.Fingerprint+" "+f.Message)
		}
		if first == nil {
			first = got
			if len(findingsIn(res, "MCPG001", "shared.py")) != 1 {
				t.Fatalf("helper analyzed %d times, want once: %+v", len(findingsIn(res, "MCPG001", "shared.py")), res.Findings)
			}
			continue
		}
		if !reflect.DeepEqual(first, got) {
			t.Fatalf("workers=%d changed the findings:\n%v\n%v", workers, first, got)
		}
	}
	// The helper is credited to the first caller in path order.
	res := scanDir(t, dir, Options{})
	if got := findingsIn(res, "MCPG001", "shared.py"); got[0] != "2 read_note0 (via read_any)" {
		t.Errorf("credited caller = %v", got)
	}
}

func TestCrossFileSkippedWhenTreeIsTooLarge(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "server.py", pyTool)
	write(t, dir, "utils.py", pyHelper)
	res := scanDir(t, dir, Options{MaxIndexBytes: 10})
	if len(findingsIn(res, "MCPG001", "utils.py")) != 0 || len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "cross-file analysis skipped") {
		t.Errorf("warnings = %v findings = %+v", res.Warnings, res.Findings)
	}
}
