package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func run(args ...string) (int, string, string) {
	var out, errOut bytes.Buffer
	code := Run(args, &out, &errOut)
	return code, out.String(), errOut.String()
}

func fixture(parts ...string) string {
	return filepath.Join(append([]string{"..", "..", "testdata", "rules"}, parts...)...)
}

func TestScanExitCodes(t *testing.T) {
	vuln := fixture("MCPG004", "vulnerable")
	if code, _, stderr := run("scan", vuln, "--no-color"); code != ExitFindings {
		t.Errorf("vulnerable scan exit = %d, want %d (stderr: %s)", code, ExitFindings, stderr)
	}
	if code, _, _ := run("scan", vuln, "--fail-on", "none"); code != ExitOK {
		t.Errorf("--fail-on none exit = %d, want 0", code)
	}
	// MCPG006 fixtures only produce medium findings: they fail at "medium" but not at "high".
	destructive := fixture("MCPG006", "vulnerable")
	if code, _, _ := run("scan", destructive, "--fail-on", "high"); code != ExitOK {
		t.Errorf("medium-only scan with --fail-on high exit = %d, want 0", code)
	}
	if code, _, _ := run("scan", destructive, "--fail-on=medium"); code != ExitFindings {
		t.Errorf("medium-only scan with --fail-on medium exit = %d, want 1", code)
	}
	for _, safe := range []string{"MCPG001", "MCPG004", "MCPG005", "MCPG008"} {
		if code, out, _ := run("scan", fixture(safe, "safe")); code != ExitOK {
			t.Errorf("%s/safe exit = %d, want 0:\n%s", safe, code, out)
		}
	}
}

func TestScanFlagsAfterPath(t *testing.T) {
	code, out, stderr := run("scan", fixture("MCPG005", "vulnerable"), "--format", "json", "--fail-on", "none")
	if code != ExitOK {
		t.Fatalf("exit = %d: %s", code, stderr)
	}
	var rep struct {
		Findings []struct {
			RuleID string `json:"rule_id"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, out)
	}
	if len(rep.Findings) == 0 {
		t.Error("expected findings in JSON output")
	}
}

func TestScanOutputFileAndConfig(t *testing.T) {
	dir := t.TempDir()
	src, err := os.ReadFile(fixture("MCPG004", "vulnerable", "shell.py"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "shell.py"), src, 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := "fail-on: critical\nseverity:\n  MCPG004: medium\n"
	if err := os.WriteFile(filepath.Join(dir, ".mcp-guard.yaml"), []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "report.sarif")
	code, _, stderr := run("scan", dir, "--format", "sarif", "-o", out)
	if code != ExitOK {
		t.Fatalf("exit = %d, want 0 (severity lowered below fail-on by config): %s", code, stderr)
	}
	b, err := os.ReadFile(out)
	if err != nil || !strings.Contains(string(b), `"version": "2.1.0"`) {
		t.Fatalf("SARIF file not written correctly: %v", err)
	}

	if err := os.WriteFile(filepath.Join(dir, ".mcp-guard.yaml"), []byte("fail_on: high\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, _, stderr := run("scan", dir); code != ExitError || !strings.Contains(stderr, "fail_on") {
		t.Errorf("unknown config key should fail with exit 2, got %d: %s", code, stderr)
	}
}

func TestCustomRulesFlag(t *testing.T) {
	dir := t.TempDir()
	rule := `rules:
  - id: ACME001
    severity: critical
    scope: file
    languages: [python]
    pattern: 'FastMCP\('
    message: "FastMCP server found"
`
	rulesPath := filepath.Join(dir, "acme.yaml")
	if err := os.WriteFile(rulesPath, []byte(rule), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, stderr := run("scan", fixture("MCPG007", "safe"), "--rules", rulesPath, "--format", "json")
	if code != ExitFindings || !strings.Contains(out, "ACME001") {
		t.Errorf("custom rule not applied (exit %d): %s %s", code, out, stderr)
	}
	if code, out, _ := run("rules", "list", "--rules", rulesPath); code != ExitOK || !strings.Contains(out, "ACME001") {
		t.Errorf("rules list should include custom rules: %s", out)
	}
}

func TestRulesAndVersion(t *testing.T) {
	code, out, _ := run("rules")
	if code != ExitOK || strings.Count(out, "MCPG") != 8 {
		t.Errorf("rules list:\n%s", out)
	}
	code, out, _ = run("rules", "explain", "mcpg003")
	if code != ExitOK || !strings.Contains(out, "hardcoded-secret") || !strings.Contains(out, "How to fix") {
		t.Errorf("rules explain:\n%s", out)
	}
	if code, _, _ := run("rules", "explain", "NOPE"); code != ExitError {
		t.Errorf("unknown rule exit = %d", code)
	}
	if code, out, _ := run("version"); code != ExitOK || !strings.HasPrefix(out, "mcp-guard ") {
		t.Errorf("version: %q", out)
	}
	if code, _, _ := run("frobnicate"); code != ExitError {
		t.Errorf("unknown command exit = %d", code)
	}
	if code, _, stderr := run("scan", "--disable", "MCPG999", fixture("MCPG001", "safe")); code != ExitError || !strings.Contains(stderr, "MCPG999") {
		t.Errorf("disabling an unknown rule should fail: %d %s", code, stderr)
	}
}
