// Package baseline records the findings of a scan so that later runs only report new ones.
// Findings are matched by fingerprint, which does not depend on line numbers, so a baseline
// survives unrelated edits to the same file.
package baseline

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"github.com/Gerijacki/mcp-guard/internal/finding"
)

const version = 1

// File is the on-disk baseline.
type File struct {
	Version  int     `json:"version"`
	Findings []Entry `json:"findings"`
}

// Entry is one accepted finding. Only Fingerprint is used for matching; the other fields
// make the file reviewable in a diff.
type Entry struct {
	Fingerprint string `json:"fingerprint"`
	RuleID      string `json:"rule_id"`
	File        string `json:"file"`
	Tool        string `json:"tool,omitempty"`
	Message     string `json:"message"`
}

// Save writes the findings as a baseline, sorted for stable diffs.
func Save(path string, fs []finding.Finding) error {
	b := File{Version: version, Findings: make([]Entry, 0, len(fs))}
	for _, f := range fs {
		b.Findings = append(b.Findings, Entry{Fingerprint: f.Fingerprint, RuleID: f.RuleID, File: f.File, Tool: f.Tool, Message: f.Message})
	}
	sort.Slice(b.Findings, func(i, j int) bool {
		a, c := b.Findings[i], b.Findings[j]
		if a.File != c.File {
			return a.File < c.File
		}
		if a.RuleID != c.RuleID {
			return a.RuleID < c.RuleID
		}
		return a.Fingerprint < c.Fingerprint
	})
	out, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(out, '\n'), 0o644)
}

// Load reads a baseline file.
func Load(path string) (*File, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var b File
	if err := json.Unmarshal(raw, &b); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if b.Version != version {
		return nil, fmt.Errorf("%s: unsupported baseline version %d (want %d)", path, b.Version, version)
	}
	return &b, nil
}

// Filter removes the findings present in the baseline. It returns the new findings, how many
// were hidden because the baseline already has them, and how many baseline entries no longer
// occur (fixed, or in files that were not scanned).
func (b *File) Filter(fs []finding.Finding) (kept []finding.Finding, hidden, gone int) {
	known := make(map[string]bool, len(b.Findings))
	for _, e := range b.Findings {
		known[e.Fingerprint] = true
	}
	present := map[string]bool{}
	for _, f := range fs {
		if known[f.Fingerprint] {
			hidden++
			present[f.Fingerprint] = true
			continue
		}
		kept = append(kept, f)
	}
	for fp := range known {
		if !present[fp] {
			gone++
		}
	}
	return kept, hidden, gone
}
