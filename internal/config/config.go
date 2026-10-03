// Package config loads the optional .mcp-guard.yaml project configuration.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// FileNames are the configuration files looked up in the scanned directory.
var FileNames = []string{".mcp-guard.yaml", ".mcp-guard.yml"}

// Config mirrors .mcp-guard.yaml. Every field is optional; CLI flags take precedence.
type Config struct {
	// FailOn is the minimum severity that makes the scan exit with code 1 ("none" disables).
	FailOn string `yaml:"fail-on"`
	// MinSeverity hides findings below this severity.
	MinSeverity string `yaml:"min-severity"`
	// Disable lists rule IDs to turn off.
	Disable []string `yaml:"disable"`
	// Severity overrides the severity of every finding of a rule, e.g. {MCPG002: low}.
	Severity map[string]string `yaml:"severity"`
	// Ignore lists glob patterns (relative to the scan root) of paths to skip.
	Ignore []string `yaml:"ignore"`
	// Rules lists custom rule files or directories, relative to the config file.
	Rules []string `yaml:"rules"`
	// IncludeTests also scans test files and directories (skipped by default).
	IncludeTests bool `yaml:"include-tests"`
	// RequireIgnoreReason ignores "mcp-guard:ignore" comments that carry no justification.
	RequireIgnoreReason bool `yaml:"require-ignore-reason"`
	// WarnUnusedIgnores reports ignore comments that no longer suppress anything.
	WarnUnusedIgnores bool `yaml:"warn-unused-ignores"`
	// Extend teaches built-in taint rules (MCPG001, 004, 005, 009, 010, 012) your own sinks and
	// sanitizers, e.g. {MCPG001: {sanitizers: ['\bsafe_join\s*\(']}}.
	Extend map[string]Extension `yaml:"extend"`
	// Lock is the lock file (see `mcp-guard lock`) checked by MCPG016, relative to the config file.
	Lock string `yaml:"lock"`
	// Overrides turn rules off for part of the tree, e.g. scripts/**: [MCPG006].
	Overrides []Override `yaml:"overrides"`

	// Path is where the config was loaded from.
	Path string `yaml:"-"`
}

// Extension lists extra sinks and sanitizers (regular expressions) for one built-in rule.
type Extension struct {
	Sinks      []string `yaml:"sinks"`
	Sanitizers []string `yaml:"sanitizers"`
}

// Override disables rules for the files matching a glob (relative to the scan root).
type Override struct {
	Path    string   `yaml:"path"`
	Disable []string `yaml:"disable"`
}

// Load reads and validates a config file. Unknown keys are rejected to catch typos.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	c.Path = path
	base := filepath.Dir(path)
	if c.Lock != "" && !filepath.IsAbs(c.Lock) {
		c.Lock = filepath.Join(base, c.Lock)
	}
	for i, r := range c.Rules {
		if !filepath.IsAbs(r) {
			c.Rules[i] = filepath.Join(base, r)
		}
	}
	return &c, nil
}

// Find returns the path of the config file in dir, or "" if there is none.
func Find(dir string) string {
	for _, name := range FileNames {
		p := filepath.Join(dir, name)
		if info, err := os.Stat(p); err == nil && !info.IsDir() {
			return p
		}
	}
	return ""
}

// FindUp looks for a config file in dir and, when dir is inside a git repository, in each
// parent up to the repository root, so that scanning a subfolder still honors the project
// config. Outside a repository only dir itself is checked.
func FindUp(dir string) string {
	if p := Find(dir); p != "" {
		return p
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return ""
	}
	root := ""
	for d := abs; ; d = filepath.Dir(d) {
		if _, err := os.Stat(filepath.Join(d, ".git")); err == nil {
			root = d
			break
		}
		if filepath.Dir(d) == d {
			return ""
		}
	}
	for d := abs; d != filepath.Dir(root) && d != filepath.Dir(d); d = filepath.Dir(d) {
		if p := Find(d); p != "" {
			return p
		}
	}
	return ""
}
