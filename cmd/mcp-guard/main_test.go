package main

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// buildBinary compiles the real binary once for the end-to-end tests below.
func buildBinary(t *testing.T) string {
	t.Helper()
	if testing.Short() {
		t.Skip("end-to-end tests build the binary; skipped with -short")
	}
	name := "mcp-guard"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	bin := filepath.Join(t.TempDir(), name)
	cmd := exec.Command("go", "build", "-o", bin, ".")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	return bin
}

func runBin(t *testing.T, bin string, args ...string) (int, string, string) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	var stdout, stderr strings.Builder
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	code := 0
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return code, stdout.String(), stderr.String()
}

func TestBinaryOnTheVulnerableExample(t *testing.T) {
	bin := buildBinary(t)
	example := filepath.Join("..", "..", "examples", "vulnerable-server")

	code, out, errOut := runBin(t, bin, "scan", example, "--format", "json")
	if code != 1 {
		t.Fatalf("exit code %d, want 1 (findings)\nstderr: %s", code, errOut)
	}
	var rep struct {
		Findings []struct {
			RuleID string `json:"rule_id"`
		}
	}
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	got := map[string]bool{}
	for _, f := range rep.Findings {
		got[f.RuleID] = true
	}
	for _, id := range []string{"MCPG001", "MCPG002", "MCPG003", "MCPG004", "MCPG005", "MCPG006", "MCPG007", "MCPG008",
		"MCPG009", "MCPG010", "MCPG011", "MCPG012", "MCPG013", "MCPG014", "MCPG015", "MCPG017"} {
		if !got[id] {
			t.Errorf("rule %s did not fire on the example server", id)
		}
	}
	if code, _, _ := runBin(t, bin, "scan", example, "--fail-on", "none"); code != 0 {
		t.Errorf("--fail-on none: exit %d", code)
	}
}

func TestBinaryExitCodesAndCommands(t *testing.T) {
	bin := buildBinary(t)
	clean := t.TempDir()
	if err := os.WriteFile(filepath.Join(clean, "ok.py"), []byte("x = 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, out, _ := runBin(t, bin, "scan", clean); code != 0 || !strings.Contains(out, "No issues found") {
		t.Errorf("clean scan: exit %d\n%s", code, out)
	}
	if code, out, _ := runBin(t, bin, "version"); code != 0 || !strings.HasPrefix(out, "mcp-guard ") {
		t.Errorf("version: exit %d %q", code, out)
	}
	if code, _, _ := runBin(t, bin, "scan", filepath.Join(clean, "missing")); code != 2 {
		t.Errorf("missing path: exit %d, want 2", code)
	}
	if code, _, errOut := runBin(t, bin, "bogus"); code != 2 || !strings.Contains(errOut, "unknown command") {
		t.Errorf("unknown command: exit %d %q", code, errOut)
	}
	if code, out, _ := runBin(t, bin, "rules", "explain", "MCPG009"); code != 0 || !strings.Contains(out, "server-side-request-forgery") {
		t.Errorf("rules explain: exit %d\n%s", code, out)
	}
	// The repository itself must stay clean (dogfooding), from the binary's point of view too.
	if code, out, _ := runBin(t, bin, "scan", filepath.Join("..", ".."), "--format", "json"); code != 0 {
		t.Errorf("the repository does not scan clean: exit %d\n%s", code, out)
	}
}
