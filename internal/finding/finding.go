// Package finding defines the result type produced by rules and its severity scale.
package finding

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// Severity ranks how bad a finding is. Higher values are more severe.
type Severity int

const (
	Info Severity = iota
	Low
	Medium
	High
	Critical
)

var severityNames = [...]string{"info", "low", "medium", "high", "critical"}

func (s Severity) String() string {
	if s < Info || s > Critical {
		return fmt.Sprintf("severity(%d)", int(s))
	}
	return severityNames[s]
}

// ParseSeverity parses a case-insensitive severity name.
func ParseSeverity(v string) (Severity, error) {
	v = strings.ToLower(strings.TrimSpace(v))
	for i, name := range severityNames {
		if v == name {
			return Severity(i), nil
		}
	}
	return Info, fmt.Errorf("unknown severity %q (want one of: %s)", v, strings.Join(severityNames[:], ", "))
}

func (s Severity) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

func (s *Severity) UnmarshalText(b []byte) error {
	v, err := ParseSeverity(string(b))
	if err != nil {
		return err
	}
	*s = v
	return nil
}

// Finding is a single issue reported by a rule.
type Finding struct {
	RuleID      string   `json:"rule_id"`
	RuleName    string   `json:"rule_name"`
	Severity    Severity `json:"severity"`
	Message     string   `json:"message"`
	File        string   `json:"file"`
	Line        int      `json:"line"`
	Snippet     string   `json:"snippet,omitempty"`
	Tool        string   `json:"tool,omitempty"`
	Fingerprint string   `json:"fingerprint"`
}

// ComputeFingerprint sets a stable identifier that survives unrelated line shifts,
// so findings can be tracked across runs (SARIF partialFingerprints, baselines).
func (f *Finding) ComputeFingerprint() {
	h := sha256.New()
	for _, part := range []string{f.RuleID, f.File, f.Tool, strings.TrimSpace(f.Snippet), f.Message} {
		h.Write([]byte(part))
		h.Write([]byte{0})
	}
	f.Fingerprint = hex.EncodeToString(h.Sum(nil))[:32]
}

// Sort orders findings by severity (most severe first), then file, line and rule.
func Sort(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if a.Severity != b.Severity {
			return a.Severity > b.Severity
		}
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		return a.RuleID < b.RuleID
	})
}

// CountBySeverity returns how many findings exist per severity name.
func CountBySeverity(fs []Finding) map[string]int {
	out := make(map[string]int, len(severityNames))
	for _, name := range severityNames {
		out[name] = 0
	}
	for _, f := range fs {
		out[f.Severity.String()]++
	}
	return out
}
