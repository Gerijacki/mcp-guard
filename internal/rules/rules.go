// Package rules contains the rule interface, the built-in MCP security checks and the
// loader for user-defined YAML rules.
package rules

import (
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/Gerijacki/mcp-guard/internal/finding"
	"github.com/Gerijacki/mcp-guard/internal/source"
)

// DocsBaseURL is where per-rule documentation lives.
const DocsBaseURL = "https://github.com/Gerijacki/mcp-guard/blob/main/docs/rules/"

// Meta describes a rule for reports, SARIF and `mcp-guard rules explain`.
type Meta struct {
	ID          string
	Name        string
	Severity    finding.Severity // default severity; individual findings may differ
	Summary     string
	Description string
	Remediation string
	CWE         []string
	// OWASP lists OWASP Top 10 identifiers: MCPxx:2025 (MCP Top 10), LLMxx:2025
	// (LLM Applications) and ASIxx:2026 (Agentic Applications). See docs/owasp.md.
	OWASP []string
	// HelpURL overrides the default documentation link (used by custom rules).
	HelpURL string
}

// Help returns the documentation URL for the rule.
func (m Meta) Help() string {
	if m.HelpURL != "" {
		return m.HelpURL
	}
	if strings.HasPrefix(m.ID, "MCPG") {
		return DocsBaseURL + m.ID + ".md"
	}
	return ""
}

// Rule is a single security check run against every scanned file.
type Rule interface {
	Meta() Meta
	Check(f *source.File) []finding.Finding
}

// Builtin returns all built-in rules, ordered by ID.
func Builtin() []Rule {
	rs := []Rule{
		fileAccessRule{},
		passthroughRule{},
		secretRule{},
		commandInjectionRule{},
		sqlInjectionRule{},
		destructiveRule{},
		poisoningRule{},
		transportRule{},
	}
	sort.Slice(rs, func(i, j int) bool { return rs[i].Meta().ID < rs[j].Meta().ID })
	return rs
}

// newFinding builds a finding for line n of f.
func newFinding(m Meta, f *source.File, n int, sev finding.Severity, tool, msg string) finding.Finding {
	return finding.Finding{
		RuleID:   m.ID,
		RuleName: m.Name,
		Severity: sev,
		Message:  msg,
		File:     f.Path,
		Line:     n,
		Snippet:  snippet(f.Line(n)),
		Tool:     tool,
	}
}

const maxSnippet = 160

// snippet trims and truncates a source line and escapes control, invisible and bidi
// characters. Scanned code is untrusted: raw ANSI escapes or bidi overrides in a
// snippet could otherwise rewrite or hide parts of mcp-guard's own terminal output.
func snippet(line string) string {
	line = strings.TrimSpace(line)
	if utf8.RuneCountInString(line) > maxSnippet {
		line = string([]rune(line)[:maxSnippet]) + "…"
	}
	return escapeInvisible(line)
}

func escapeInvisible(s string) string {
	var b strings.Builder
	for _, c := range s {
		switch {
		case c == '\t':
			b.WriteRune(c)
		case c < 0x20 || c == 0x7f || (c >= 0x80 && c < 0xa0) || invisibleChars(string(c)) != "":
			if c > 0xFFFF {
				fmt.Fprintf(&b, `\U%08X`, c)
			} else {
				fmt.Fprintf(&b, `\u%04X`, c)
			}
		default:
			b.WriteRune(c)
		}
	}
	return b.String()
}

// toolBodies yields the tools of f that have a known handler body.
func toolBodies(f *source.File) []source.Tool {
	var out []source.Tool
	for _, t := range f.Tools {
		if t.HasBody() {
			out = append(out, t)
		}
	}
	return out
}
