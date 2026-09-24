package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Gerijacki/mcp-guard/internal/finding"
	"github.com/Gerijacki/mcp-guard/internal/rules"
	"github.com/Gerijacki/mcp-guard/internal/scanner"
)

func sampleResult() *scanner.Result {
	var metas []rules.Meta
	for _, r := range rules.Builtin() {
		metas = append(metas, r.Meta())
	}
	f := finding.Finding{
		RuleID: "MCPG004", RuleName: "command-injection", Severity: finding.Critical,
		Message: "Tool \"run\" interpolates model-controlled \"cmd\" into a shell command (command injection).",
		File:    "src/server.py", Line: 12, Snippet: "os.system(cmd)", Tool: "run",
	}
	f.ComputeFingerprint()
	return &scanner.Result{Findings: []finding.Finding{f}, FilesScanned: 3, ToolsFound: 2, Rules: metas}
}

func TestSARIF(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, "sarif", sampleResult(), Options{Version: "1.2.3"}); err != nil {
		t.Fatal(err)
	}
	var log struct {
		Schema  string `json:"$schema"`
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name  string `json:"name"`
					Rules []struct {
						ID         string `json:"id"`
						Properties struct {
							Tags             []string `json:"tags"`
							SecuritySeverity string   `json:"security-severity"`
						} `json:"properties"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID    string `json:"ruleId"`
				RuleIndex int    `json:"ruleIndex"`
				Level     string `json:"level"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
						Region struct {
							StartLine int `json:"startLine"`
						} `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
				PartialFingerprints map[string]string `json:"partialFingerprints"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if log.Version != "2.1.0" || !strings.Contains(log.Schema, "sarif-2.1.0") || len(log.Runs) != 1 {
		t.Fatalf("bad envelope: %+v", log)
	}
	run := log.Runs[0]
	if run.Tool.Driver.Name != "mcp-guard" || len(run.Tool.Driver.Rules) != 8 {
		t.Fatalf("bad driver: %+v", run.Tool.Driver)
	}
	if len(run.Results) != 1 {
		t.Fatalf("results = %d", len(run.Results))
	}
	r := run.Results[0]
	if r.RuleID != "MCPG004" || run.Tool.Driver.Rules[r.RuleIndex].ID != "MCPG004" || r.Level != "error" {
		t.Errorf("bad result: %+v", r)
	}
	loc := r.Locations[0].PhysicalLocation
	if loc.ArtifactLocation.URI != "src/server.py" || loc.Region.StartLine != 12 {
		t.Errorf("bad location: %+v", loc)
	}
	if r.PartialFingerprints["mcpGuardFingerprint/v1"] == "" {
		t.Error("missing fingerprint")
	}
	rule := run.Tool.Driver.Rules[r.RuleIndex]
	if rule.Properties.SecuritySeverity != "9.5" || !contains(rule.Properties.Tags, "external/cwe/cwe-78") ||
		!contains(rule.Properties.Tags, "external/owasp/mcp05:2025") {
		t.Errorf("bad rule properties: %+v", rule.Properties)
	}
}

func TestJSONEmptyFindingsIsArray(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, "json", &scanner.Result{}, Options{Version: "dev"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), `"findings": []`) {
		t.Errorf("findings should be an empty array:\n%s", buf.String())
	}
}

func TestText(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, "text", sampleResult(), Options{Version: "dev"}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"CRITICAL", "MCPG004", "src/server.py:12", "(tool: run)", "os.system(cmd)", "Found 1 issue:"} {
		if !strings.Contains(out, want) {
			t.Errorf("text output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "\x1b[") {
		t.Error("colors must be off when Color is false")
	}
}

func TestUnknownFormat(t *testing.T) {
	if err := Write(&bytes.Buffer{}, "xml", &scanner.Result{}, Options{}); err == nil {
		t.Error("expected error for unknown format")
	}
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func TestTextColorsUseEscapeSequences(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, "text", sampleResult(), Options{Version: "dev", Color: true}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	esc := string(rune(0x1b))
	if strings.Contains(strings.ReplaceAll(out, esc+"[", ""), "[1;") {
		t.Errorf("found an ANSI code without its ESC byte:\n%q", out)
	}
	if !strings.Contains(out, esc+"[1;91m1 critical") {
		t.Errorf("summary is not colored:\n%q", out)
	}
}
