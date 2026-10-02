package rules

import (
	"fmt"

	"github.com/Gerijacki/mcp-guard/internal/finding"
	"github.com/Gerijacki/mcp-guard/internal/lock"
	"github.com/Gerijacki/mcp-guard/internal/source"
)

// MCPG016: a tool definition or server launch command differs from the reviewed lock file
// (rug pull). The rule only produces findings when a lock is supplied (scan --lock).
type definitionChangedRule struct {
	lock *lock.File
	root string
}

func (definitionChangedRule) Meta() Meta {
	return Meta{
		ID:       "MCPG016",
		Name:     "definition-changed-since-lock",
		Severity: finding.High,
		Summary:  "Tool description, parameters or server launch command changed since the lock file",
		Description: "A tool's description is read by the model on every session but rarely re-read by people, so an " +
			"attacker (or a compromised dependency) can publish a harmless tool, wait until it is approved, " +
			"then change the description to carry instructions (a rug pull). Likewise a client-config entry that " +
			"launches a different package version or command runs different code. mcp-guard.lock records what " +
			"was reviewed; any difference is reported until the lock is deliberately regenerated.",
		Remediation: "Read the new description or command. If it is legitimate, review the change and refresh the lock " +
			"with `mcp-guard lock` in the same commit; if you did not expect it, treat the server as compromised.",
		CWE:   []string{"CWE-494", "CWE-1427"},
		OWASP: []string{"MCP03:2025", "LLM03:2025", "ASI04:2026"},
	}
}

// WithLock returns rs with the lock file l (for scans rooted at root) attached to MCPG016.
func WithLock(rs []Rule, l *lock.File, root string) []Rule {
	out := make([]Rule, len(rs))
	for i, r := range rs {
		if _, ok := r.(definitionChangedRule); ok {
			r = definitionChangedRule{lock: l, root: root}
		}
		out[i] = r
	}
	return out
}

func (r definitionChangedRule) Check(f *source.File) []finding.Finding {
	if r.lock == nil {
		return nil
	}
	rel := lock.RelPath(r.root, f.Path)
	var out []finding.Finding
	for _, t := range f.Tools {
		line := t.DescriptionLine
		if line == 0 {
			line = t.Line
		}
		change, old := r.lock.Compare(lock.ToolEntry(rel, t))
		switch change {
		case lock.TextChanged:
			msg := fmt.Sprintf("Description of %s %q changed since the lock file was written (possible rug pull); review the new text", lowerNoun(t), t.Name)
			if old.Description != "" {
				msg += fmt.Sprintf(" (it used to say: %q)", old.Description)
			}
			out = append(out, newFinding(r.Meta(), f, line, finding.High, t.Name, msg+"."))
		case lock.ShapeChanged:
			out = append(out, newFinding(r.Meta(), f, t.Line, finding.Medium, t.Name, fmt.Sprintf(
				"Parameters or annotations of %s %q changed since the lock file was written; review whether the model now has access to more.", lowerNoun(t), t.Name)))
		case lock.New:
			out = append(out, newFinding(r.Meta(), f, t.Line, finding.Low, t.Name, fmt.Sprintf(
				"%s %q is not in the lock file: review it and run `mcp-guard lock`.", t.Noun(), t.Name)))
		}
	}
	for _, s := range f.Servers {
		change, _ := r.lock.Compare(lock.ServerEntry(rel, s))
		switch change {
		case lock.TextChanged, lock.ShapeChanged:
			out = append(out, newFinding(r.Meta(), f, s.Line, finding.High, "", fmt.Sprintf(
				"MCP server %q now launches differently (command, arguments or URL) than when the lock file was written; review the change.", s.Name)))
		case lock.New:
			out = append(out, newFinding(r.Meta(), f, s.Line, finding.Medium, "", fmt.Sprintf(
				"MCP server %q is not in the lock file: review it and run `mcp-guard lock`.", s.Name)))
		}
	}
	return out
}

func lowerNoun(t source.Tool) string {
	switch t.Kind {
	case "resource":
		return "resource"
	case "prompt":
		return "prompt"
	}
	return "tool"
}
