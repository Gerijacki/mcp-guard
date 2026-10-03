package scanner

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/Gerijacki/mcp-guard/internal/finding"
	"github.com/Gerijacki/mcp-guard/internal/source"
)

// Inline suppressions are comments:
//
//	x = run(cmd)  # mcp-guard:ignore MCPG004 -- fixed allowlist, reviewed
//	# mcp-guard:ignore-next-line MCPG001
//	# mcp-guard:ignore-file MCPG006 -- demo server
//
// A directive without rule IDs suppresses every rule. Matching text inside a string
// literal is not a suppression.
var (
	ignoreRe = regexp.MustCompile(`mcp-guard:ignore(-next-line|-file)?\b([^\n]*)`)
	ruleIDRe = regexp.MustCompile(`\b[A-Z][A-Z0-9_-]{2,31}\b`)
)

type directive struct {
	line   int
	kind   string // "", "-next-line", "-file"
	ids    []string
	reason string
	used   bool
}

func (d *directive) covers(line int, ruleID string) bool {
	switch d.kind {
	case "-file":
	case "-next-line":
		if line != d.line+1 {
			return false
		}
	default:
		if line != d.line && line != d.line+1 {
			return false
		}
	}
	if len(d.ids) == 0 {
		return true
	}
	for _, id := range d.ids {
		if id == ruleID {
			return true
		}
	}
	return false
}

// directives parses the suppression comments of f.
func directives(f *source.File) []*directive {
	if !strings.Contains(f.Content, "mcp-guard:ignore") {
		return nil
	}
	var out []*directive
	for i, line := range f.Lines {
		loc := ignoreRe.FindStringSubmatchIndex(line)
		if loc == nil || !f.InComment(i+1, loc[0], loc[1]) {
			continue
		}
		rest := line[loc[4]:loc[5]]
		d := &directive{line: i + 1}
		if loc[2] >= 0 { // the optional -next-line / -file suffix
			d.kind = line[loc[2]:loc[3]]
		}
		head, reason, _ := strings.Cut(rest, "--")
		d.ids = ruleIDRe.FindAllString(head, -1)
		// Free text after the IDs also counts as the reason ("ignore MCPG004 vetted allowlist").
		words := strings.TrimSpace(strings.Trim(ruleIDRe.ReplaceAllString(head, ""), " \t[]:,*/"))
		d.reason = strings.TrimSpace(strings.Trim(reason, " \t*/"))
		if d.reason == "" {
			d.reason = words
		}
		out = append(out, d)
	}
	return out
}

// suppress drops the findings covered by an ignore comment. With requireReason, a comment
// without a justification is not honored. It returns warnings about such comments and, with
// warnUnused, about comments that suppress nothing.
func suppress(f *source.File, fs []finding.Finding, requireReason, warnUnused bool) ([]finding.Finding, []string) {
	ds := directives(f)
	if len(ds) == 0 {
		return fs, nil
	}
	var warnings []string
	active := ds[:0:0]
	for _, d := range ds {
		if requireReason && d.reason == "" {
			warnings = append(warnings, fmt.Sprintf("%s:%d: mcp-guard:ignore ignored: add a reason after the rule ID (require-ignore-reason is on)", f.Path, d.line))
			continue
		}
		active = append(active, d)
	}
	out := fs[:0]
	for _, fd := range fs {
		hidden := false
		for _, d := range active {
			if d.covers(fd.Line, fd.RuleID) {
				d.used, hidden = true, true
			}
		}
		if !hidden {
			out = append(out, fd)
		}
	}
	if warnUnused {
		for _, d := range active {
			if !d.used {
				warnings = append(warnings, fmt.Sprintf("%s:%d: unused mcp-guard:ignore (nothing to suppress)", f.Path, d.line))
			}
		}
	}
	return out, warnings
}
