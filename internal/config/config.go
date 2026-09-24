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

	// Path is where the config was loaded from.
	Path string `yaml:"-"`
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
