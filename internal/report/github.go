package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/Gerijacki/mcp-guard/internal/finding"
	"github.com/Gerijacki/mcp-guard/internal/scanner"
)

// writeGitHub prints GitHub Actions workflow commands, so findings show up as annotations
// on the pull request without needing code scanning.
func writeGitHub(w io.Writer, res *scanner.Result) error {
	for _, f := range res.Findings {
		level := "notice"
		switch {
		case f.Severity >= finding.High:
			level = "error"
		case f.Severity == finding.Medium:
			level = "warning"
		}
		_, err := fmt.Fprintf(w, "::%s file=%s,line=%d,title=%s::%s\n", level, ghProp(f.File), f.Line,
			ghProp(f.RuleID+" "+f.RuleName), ghData(f.Message))
		if err != nil {
			return err
		}
	}
	for _, wmsg := range res.Warnings {
		if _, err := fmt.Fprintf(w, "::warning::%s\n", ghData(wmsg)); err != nil {
			return err
		}
	}
	return nil
}

// Workflow command escaping: https://docs.github.com/actions/reference/workflow-commands-for-github-actions
func ghData(s string) string {
	return strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A").Replace(s)
}

func ghProp(s string) string {
	return strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A", ":", "%3A", ",", "%2C").Replace(s)
}
