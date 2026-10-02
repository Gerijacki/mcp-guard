package rules

import (
	"fmt"
	"strings"

	"github.com/Gerijacki/mcp-guard/internal/finding"
	"github.com/Gerijacki/mcp-guard/internal/source"
)

// MCPG017: one file registers two tools (or resources, prompts) with the same name.
//
// Only a single file is compared: one file is one server, whereas the same name in two files
// of a repository is usually two different example servers.
type duplicateToolRule struct{}

func (duplicateToolRule) Meta() Meta {
	return Meta{
		ID:       "MCPG017",
		Name:     "duplicate-tool-name",
		Severity: finding.Low,
		Summary:  "The same tool name is registered twice in one file",
		Description: "When two tools registered on one server share a name, the SDK keeps one and the model cannot tell " +
			"them apart: the later definition silently shadows (or is shadowed by) the earlier one. This is " +
			"how a tool is replaced by a copy with different behavior or a different description, and it is " +
			"usually a copy-paste mistake.",
		Remediation: "Give each tool a unique, specific name, or register it once. If the two definitions are alternatives " +
			"selected by configuration, suppress the finding with a comment that says so.",
		CWE:   []string{"CWE-694"},
		OWASP: []string{"MCP03:2025", "ASI02:2026"},
	}
}

// maxScopeLines bounds how far apart two registrations may be to count as duplicates.
const maxScopeLines = 2000

// sameScope reports whether nothing between the two registrations closes the block the
// first one is in: documentation files often hold several independent examples (one function
// each) that all register a tool called "ping" on their own server.
func sameScope(f *source.File, from, to int) bool {
	if to-from > maxScopeLines {
		return false // far apart: not worth a quadratic scan, and rarely the same server
	}
	indent := min(source.Indent(f.Line(from)), source.Indent(f.Line(to)))
	for n := from + 1; n < to; n++ {
		line := f.Line(n)
		if strings.TrimSpace(line) != "" && source.Indent(line) < indent {
			return false
		}
	}
	return true
}

func (r duplicateToolRule) Check(f *source.File) []finding.Finding {
	type key struct{ kind, name, receiver string }
	// Each registration is compared with the previous one of the same name, so the lines in
	// between are scanned once overall (a file full of identical tools stays linear).
	prev := map[key]int{}
	var out []finding.Finding
	for _, t := range f.Tools {
		if t.Dispatcher || t.Name == "" {
			continue
		}
		k := key{t.Kind, t.Name, t.Receiver} // another receiver is another server
		if line, dup := prev[k]; dup && line != t.Line && sameScope(f, line, t.Line) {
			out = append(out, newFinding(r.Meta(), f, t.Line, finding.Low, t.Name, fmt.Sprintf(
				"%s %q is registered twice in this file (previously at line %d): the later definition shadows the earlier one.", t.Noun(), t.Name, line)))
		}
		prev[k] = t.Line
	}
	return out
}
