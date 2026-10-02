package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, ".mcp-guard.yaml")
	write(t, p, `fail-on: critical
min-severity: medium
disable: [MCPG006]
severity:
  MCPG002: low
ignore: ["examples/"]
include-tests: true
rules: [rules/, /abs/rules.yaml]
`)
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.FailOn != "critical" || c.MinSeverity != "medium" || !c.IncludeTests || c.Path != p {
		t.Errorf("config = %+v", c)
	}
	if len(c.Disable) != 1 || c.Severity["MCPG002"] != "low" || c.Ignore[0] != "examples/" {
		t.Errorf("config = %+v", c)
	}
	if c.Rules[0] != filepath.Join(dir, "rules") {
		t.Errorf("relative rule path not resolved against the config file: %q", c.Rules[0])
	}
}

func TestLoadRejectsUnknownKeys(t *testing.T) {
	p := filepath.Join(t.TempDir(), ".mcp-guard.yaml")
	write(t, p, "fail_on: high\n")
	if _, err := Load(p); err == nil || !strings.Contains(err.Error(), "fail_on") {
		t.Errorf("expected an unknown-key error, got %v", err)
	}
}

func TestLoadEmptyAndMissing(t *testing.T) {
	p := filepath.Join(t.TempDir(), ".mcp-guard.yaml")
	write(t, p, "")
	if c, err := Load(p); err != nil || c.FailOn != "" {
		t.Errorf("empty config: %+v, %v", c, err)
	}
	if _, err := Load(filepath.Join(t.TempDir(), "missing.yaml")); err == nil {
		t.Error("expected an error for a missing file")
	}
}

func TestFind(t *testing.T) {
	dir := t.TempDir()
	if got := Find(dir); got != "" {
		t.Errorf("Find in empty dir = %q", got)
	}
	write(t, filepath.Join(dir, ".mcp-guard.yml"), "fail-on: low\n")
	if got := Find(dir); filepath.Base(got) != ".mcp-guard.yml" {
		t.Errorf("Find = %q", got)
	}
	write(t, filepath.Join(dir, ".mcp-guard.yaml"), "fail-on: low\n")
	if got := Find(dir); filepath.Base(got) != ".mcp-guard.yaml" {
		t.Errorf(".yaml should take precedence, got %q", got)
	}
}

func TestFindUpStopsAtGitRoot(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(root, "a", "b")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if got := FindUp(sub); got != "" {
		t.Errorf("no config anywhere, got %q", got)
	}
	cfg := filepath.Join(root, ".mcp-guard.yaml")
	if err := os.WriteFile(cfg, []byte("fail-on: low\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := FindUp(sub); got != cfg {
		t.Errorf("FindUp(%s) = %q, want %q", sub, got, cfg)
	}
	// A closer config wins.
	near := filepath.Join(root, "a", ".mcp-guard.yml")
	os.WriteFile(near, []byte("fail-on: none\n"), 0o644)
	if got := FindUp(sub); got != near {
		t.Errorf("closest config should win, got %q", got)
	}
}

func TestFindUpWithoutGitChecksOnlyTheDirectory(t *testing.T) {
	outer := t.TempDir()
	os.WriteFile(filepath.Join(outer, ".mcp-guard.yaml"), []byte("fail-on: low\n"), 0o644)
	inner := filepath.Join(outer, "inner")
	os.MkdirAll(inner, 0o755)
	if got := FindUp(inner); got != "" {
		t.Errorf("outside a git repo parents must not be searched, got %q", got)
	}
}

func TestLoadOverridesAndIgnoreOptions(t *testing.T) {
	p := filepath.Join(t.TempDir(), ".mcp-guard.yaml")
	os.WriteFile(p, []byte("require-ignore-reason: true\nwarn-unused-ignores: true\noverrides:\n  - path: scripts/**\n    disable: [MCPG006]\n"), 0o644)
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if !c.RequireIgnoreReason || !c.WarnUnusedIgnores || len(c.Overrides) != 1 || c.Overrides[0].Path != "scripts/**" || c.Overrides[0].Disable[0] != "MCPG006" {
		t.Errorf("config = %+v", c)
	}
}
