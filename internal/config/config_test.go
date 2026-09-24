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
