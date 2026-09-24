package report

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	"github.com/Gerijacki/mcp-guard/internal/finding"
	"github.com/Gerijacki/mcp-guard/internal/scanner"
)

const (
	reset = "\x1b[0m"
	bold  = "\x1b[1m"
	dim   = "\x1b[2m"
)

var sevStyle = map[finding.Severity]string{
	finding.Critical: "\x1b[1;37;41m",
	finding.High:     "\x1b[1;31m",
	finding.Medium:   "\x1b[1;33m",
	finding.Low:      "\x1b[1;36m",
	finding.Info:     "\x1b[2m",
}

// summaryStyle uses foreground colors only: inline background badges are hard to read
// in many terminal themes.
var summaryStyle = map[finding.Severity]string{
	finding.Critical: "\x1b[1;91m",
	finding.High:     "\x1b[1;31m",
	finding.Medium:   "\x1b[1;33m",
	finding.Low:      "\x1b[1;36m",
	finding.Info:     "\x1b[2m",
}

func writeText(w io.Writer, res *scanner.Result, opts Options) error {
	bw := bufio.NewWriter(w)
	paint := func(style, s string) string {
		if !opts.Color || style == "" {
			return s
		}
		return style + s + reset
	}
	help := map[string]string{}
	for _, m := range res.Rules {
		help[m.ID] = m.Help()
	}

	fmt.Fprintf(bw, "%s %s  ·  %s  ·  %s  ·  %s\n\n", paint(bold, "mcp-guard"), opts.Version,
		plural(res.FilesScanned, "file"), plural(res.ToolsFound, "MCP tool"), plural(res.ConfigsFound, "client config"))

	for _, f := range res.Findings {
		label := fmt.Sprintf(" %-8s ", strings.ToUpper(f.Severity.String()))
		fmt.Fprintf(bw, "%s %s %s\n", paint(sevStyle[f.Severity], label), paint(bold, f.RuleID), f.RuleName)
		loc := fmt.Sprintf("%s:%d", f.File, f.Line)
		if f.Tool != "" {
			loc += paint(dim, fmt.Sprintf("  (tool: %s)", f.Tool))
		}
		fmt.Fprintf(bw, "  %s\n", loc)
		fmt.Fprintf(bw, "  %s\n", f.Message)
		if f.Snippet != "" {
			fmt.Fprintf(bw, "  %s %s\n", paint(dim, fmt.Sprintf("%4d │", f.Line)), f.Snippet)
		}
		if u := help[f.RuleID]; u != "" {
			fmt.Fprintf(bw, "  %s\n", paint(dim, "→ "+u))
		}
		fmt.Fprintln(bw)
	}

	if len(res.Findings) == 0 {
		fmt.Fprintln(bw, paint("\x1b[1;32m", "✓ No issues found."))
	} else {
		counts := finding.CountBySeverity(res.Findings)
		var parts []string
		for s := finding.Critical; s >= finding.Info; s-- {
			if n := counts[s.String()]; n > 0 {
				parts = append(parts, paint(summaryStyle[s], fmt.Sprintf("%d %s", n, s)))
			}
		}
		fmt.Fprintf(bw, "%s %s\n", paint(bold, "Found "+plural(len(res.Findings), "issue")+":"), strings.Join(parts, ", "))
	}
	return bw.Flush()
}

func plural(n int, noun string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, noun)
	}
	return fmt.Sprintf("%d %ss", n, noun)
}
