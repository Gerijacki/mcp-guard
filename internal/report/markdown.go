package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/Gerijacki/mcp-guard/internal/finding"
	"github.com/Gerijacki/mcp-guard/internal/scanner"
)

// writeMarkdown renders a report for pull request comments and job summaries.
func writeMarkdown(w io.Writer, res *scanner.Result, opts Options) error {
	var b strings.Builder
	fmt.Fprintf(&b, "## mcp-guard %s\n\n", opts.Version)
	fmt.Fprintf(&b, "%s, %s, %s scanned.\n\n", plural(res.FilesScanned, "file"), plural(res.ToolsFound, "MCP tool"), plural(res.ConfigsFound, "client config"))
	if len(res.Findings) == 0 {
		b.WriteString("No issues found.\n")
	} else {
		counts := finding.CountBySeverity(res.Findings)
		var parts []string
		for s := finding.Critical; s >= finding.Info; s-- {
			if n := counts[s.String()]; n > 0 {
				parts = append(parts, fmt.Sprintf("%d %s", n, s))
			}
		}
		fmt.Fprintf(&b, "**%s:** %s\n\n", plural(len(res.Findings), "issue"), strings.Join(parts, ", "))
		b.WriteString("| Severity | Rule | Location | Message |\n|---|---|---|---|\n")
		for _, f := range res.Findings {
			fmt.Fprintf(&b, "| %s | %s | `%s:%d` | %s |\n", f.Severity, f.RuleID, mdEscape(f.File), f.Line, mdEscape(f.Message))
		}
	}
	if res.Baselined > 0 {
		fmt.Fprintf(&b, "\n%s hidden by the baseline.\n", plural(res.Baselined, "existing finding"))
	}
	if n := res.Skipped.Total(); n > 0 {
		fmt.Fprintf(&b, "\n%s skipped (%s).\n", plural(n, "file"), skippedDetail(res.Skipped))
	}
	_, err := io.WriteString(w, b.String())
	return err
}

func mdEscape(s string) string {
	return strings.NewReplacer("|", "\\|", "\n", " ", "`", "'").Replace(s)
}
