package report

import (
	"encoding/json"
	"io"

	"github.com/Gerijacki/mcp-guard/internal/finding"
	"github.com/Gerijacki/mcp-guard/internal/scanner"
)

type jsonReport struct {
	Tool     string            `json:"tool"`
	Version  string            `json:"version"`
	Summary  jsonSummary       `json:"summary"`
	Findings []finding.Finding `json:"findings"`
}

type jsonSummary struct {
	FilesScanned int            `json:"files_scanned"`
	ToolsFound   int            `json:"tools_found"`
	ConfigsFound int            `json:"configs_found"`
	Findings     int            `json:"findings"`
	BySeverity   map[string]int `json:"by_severity"`
}

func writeJSON(w io.Writer, res *scanner.Result, opts Options) error {
	fs := res.Findings
	if fs == nil {
		fs = []finding.Finding{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(jsonReport{
		Tool:    "mcp-guard",
		Version: opts.Version,
		Summary: jsonSummary{
			FilesScanned: res.FilesScanned,
			ToolsFound:   res.ToolsFound,
			ConfigsFound: res.ConfigsFound,
			Findings:     len(fs),
			BySeverity:   finding.CountBySeverity(fs),
		},
		Findings: fs,
	})
}
