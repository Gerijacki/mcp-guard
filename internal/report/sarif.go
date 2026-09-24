package report

import (
	"encoding/json"
	"io"
	"strings"

	"github.com/Gerijacki/mcp-guard/internal/finding"
	"github.com/Gerijacki/mcp-guard/internal/rules"
	"github.com/Gerijacki/mcp-guard/internal/scanner"
)

// SARIF 2.1.0, as consumed by GitHub code scanning and most CI security dashboards.

const (
	sarifSchema  = "https://json.schemastore.org/sarif-2.1.0.json"
	sarifVersion = "2.1.0"
	infoURI      = "https://github.com/Gerijacki/mcp-guard"
)

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Version        string      `json:"version,omitempty"`
	Rules          []sarifRule `json:"rules"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifHelp struct {
	Text     string `json:"text"`
	Markdown string `json:"markdown,omitempty"`
}

type sarifRule struct {
	ID                   string         `json:"id"`
	Name                 string         `json:"name"`
	ShortDescription     sarifText      `json:"shortDescription"`
	FullDescription      sarifText      `json:"fullDescription"`
	Help                 sarifHelp      `json:"help"`
	HelpURI              string         `json:"helpUri,omitempty"`
	DefaultConfiguration sarifConfig    `json:"defaultConfiguration"`
	Properties           sarifRuleProps `json:"properties"`
}

type sarifConfig struct {
	Level string `json:"level"`
}

type sarifRuleProps struct {
	Tags             []string `json:"tags"`
	Precision        string   `json:"precision"`
	SecuritySeverity string   `json:"security-severity"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	RuleIndex           int               `json:"ruleIndex"`
	Level               string            `json:"level"`
	Message             sarifText         `json:"message"`
	Locations           []sarifLocation   `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
	Properties          map[string]string `json:"properties,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           sarifRegion   `json:"region"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int        `json:"startLine"`
	Snippet   *sarifText `json:"snippet,omitempty"`
}

func sarifLevel(s finding.Severity) string {
	switch {
	case s >= finding.High:
		return "error"
	case s == finding.Medium:
		return "warning"
	}
	return "note"
}

// securitySeverity maps to GitHub's numeric scale (critical >= 9.0, high >= 7.0, medium >= 4.0).
func securitySeverity(s finding.Severity) string {
	return map[finding.Severity]string{
		finding.Critical: "9.5", finding.High: "8.0", finding.Medium: "5.5", finding.Low: "3.0", finding.Info: "1.0",
	}[s]
}

func writeSARIF(w io.Writer, res *scanner.Result, opts Options) error {
	index := map[string]int{}
	driver := sarifDriver{Name: "mcp-guard", InformationURI: infoURI, Version: opts.Version, Rules: []sarifRule{}}
	for i, m := range res.Rules {
		index[m.ID] = i
		tags := []string{"security", "mcp"}
		for _, cwe := range m.CWE {
			tags = append(tags, "external/cwe/"+strings.ToLower(cwe))
		}
		for _, id := range m.OWASP {
			tags = append(tags, "external/owasp/"+strings.ToLower(id))
		}
		full := m.Description
		if full == "" {
			full = m.Summary
		}
		driver.Rules = append(driver.Rules, sarifRule{
			ID:                   m.ID,
			Name:                 m.Name,
			ShortDescription:     sarifText{m.Summary},
			FullDescription:      sarifText{full},
			Help:                 sarifHelp{Text: m.Remediation, Markdown: helpMarkdown(m)},
			HelpURI:              m.Help(),
			DefaultConfiguration: sarifConfig{Level: sarifLevel(m.Severity)},
			Properties:           sarifRuleProps{Tags: tags, Precision: "medium", SecuritySeverity: securitySeverity(m.Severity)},
		})
	}
	results := []sarifResult{}
	for _, f := range res.Findings {
		r := sarifResult{
			RuleID:    f.RuleID,
			RuleIndex: index[f.RuleID],
			Level:     sarifLevel(f.Severity),
			Message:   sarifText{f.Message},
			Locations: []sarifLocation{{PhysicalLocation: sarifPhysical{
				ArtifactLocation: sarifArtifact{URI: f.File},
				Region:           sarifRegion{StartLine: f.Line},
			}}},
			PartialFingerprints: map[string]string{"mcpGuardFingerprint/v1": f.Fingerprint},
			Properties:          map[string]string{"severity": f.Severity.String()},
		}
		if f.Snippet != "" {
			r.Locations[0].PhysicalLocation.Region.Snippet = &sarifText{f.Snippet}
		}
		if f.Tool != "" {
			r.Properties["tool"] = f.Tool
		}
		results = append(results, r)
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(sarifLog{
		Schema:  sarifSchema,
		Version: sarifVersion,
		Runs:    []sarifRun{{Tool: sarifTool{Driver: driver}, Results: results}},
	})
}

func helpMarkdown(m rules.Meta) string {
	var b strings.Builder
	b.WriteString("**" + m.Summary + "**\n\n")
	if m.Description != "" {
		b.WriteString(m.Description + "\n\n")
	}
	if m.Remediation != "" {
		b.WriteString("**Remediation:** " + m.Remediation + "\n")
	}
	if u := m.Help(); u != "" {
		b.WriteString("\n[Rule documentation](" + u + ")\n")
	}
	return b.String()
}
