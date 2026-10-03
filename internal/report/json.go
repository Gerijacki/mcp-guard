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
	// Warnings lists files that could not be analyzed completely (unreadable, timed out, internal errors).
	Warnings []string `json:"warnings"`
}

type jsonSummary struct {
	FilesScanned int            `json:"files_scanned"`
	ToolsFound   int            `json:"tools_found"`
	Resources    int            `json:"resources_found"`
	Prompts      int            `json:"prompts_found"`
	ConfigsFound int            `json:"configs_found"`
	Findings     int            `json:"findings"`
	BySeverity   map[string]int `json:"by_severity"`
	FilesSkipped int            `json:"files_skipped"`
	Baselined    int            `json:"baselined,omitempty"`
	BaselineGone int            `json:"baseline_fixed,omitempty"`
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
			Resources:    res.ResourcesFound,
			Prompts:      res.PromptsFound,
			ConfigsFound: res.ConfigsFound,
			Findings:     len(fs),
			BySeverity:   finding.CountBySeverity(fs),
			FilesSkipped: res.Skipped.Total(),
			Baselined:    res.Baselined,
			BaselineGone: res.Fixed,
		},
		Findings: fs,
		Warnings: warnings(res),
	})
}

func warnings(res *scanner.Result) []string {
	if res.Warnings == nil {
		return []string{}
	}
	return res.Warnings
}
