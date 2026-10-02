package report

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/Gerijacki/mcp-guard/internal/finding"
	"github.com/Gerijacki/mcp-guard/internal/rules"
	"github.com/Gerijacki/mcp-guard/internal/scanner"
)

var update = flag.Bool("update", false, "rewrite golden files")

// resultWithEverything has findings of every severity, a warning and skipped files, so the
// golden files cover all the optional parts of the output.
func resultWithEverything() *scanner.Result {
	res := sampleResult()
	// Fixed rule metadata keeps the golden files independent of the wording of real rules.
	res.Rules = []rules.Meta{
		{ID: "MCPG001", Name: "unrestricted-file-access", Severity: finding.High, Summary: "File access", Description: "Long description.", Remediation: "Fix it.", CWE: []string{"CWE-22"}, OWASP: []string{"MCP02:2025"}},
		{ID: "MCPG004", Name: "command-injection", Severity: finding.Critical, Summary: "Command injection", Description: "Long description.", Remediation: "Fix it.", CWE: []string{"CWE-78"}, OWASP: []string{"MCP05:2025"}},
		{ID: "MCPG008", Name: "exposed-network-transport", Severity: finding.Medium, Summary: "Exposed transport", Description: "Long description.", Remediation: "Fix it.", CWE: []string{"CWE-306"}, OWASP: []string{"MCP07:2025"}},
	}
	mk := func(rule, name string, sev finding.Severity, file string, line int, tool, msg string) finding.Finding {
		f := finding.Finding{RuleID: rule, RuleName: name, Severity: sev, File: file, Line: line, Tool: tool, Message: msg, Snippet: "x = 1"}
		f.ComputeFingerprint()
		return f
	}
	res.Findings = append(res.Findings,
		mk("MCPG001", "unrestricted-file-access", finding.Medium, "src/files.py", 7, "read_file", "Tool \"read_file\" reads a model-controlled path | with a pipe."),
		mk("MCPG008", "exposed-network-transport", finding.Low, "src/web.ts", 30, "", "Server listens on all interfaces."),
	)
	finding.Sort(res.Findings)
	res.Warnings = []string{"src/big.py: skipped, analysis took longer than 10s"}
	res.Skipped = scanner.SkipCounts{TimedOut: 1, TooLarge: 2}
	res.Baselined = 3
	return res
}

func golden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run: go test ./internal/report -update)", err)
	}
	if strings.ReplaceAll(string(want), "\r\n", "\n") != got { // checkouts with autocrlf (Windows) rewrite line endings
		t.Errorf("%s differs from the golden file; if the change is intended run: go test ./internal/report -update\n--- got ---\n%s", name, got)
	}
}

func render(t *testing.T, format string) string {
	t.Helper()
	var buf bytes.Buffer
	if err := Write(&buf, format, resultWithEverything(), Options{Version: "test"}); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

func TestGoldenOutputs(t *testing.T) {
	for format, file := range map[string]string{"sarif": "report.sarif.json", "json": "report.json", "markdown": "report.md", "github": "report.github", "text": "report.txt"} {
		golden(t, file, render(t, format))
	}
}

// TestSARIFConformance checks the SARIF 2.1.0 requirements for the subset mcp-guard emits
// (https://docs.oasis-open.org/sarif/sarif/v2.1.0/): required properties, enumerations,
// cross references and the URI rules GitHub code scanning relies on.
func TestSARIFConformance(t *testing.T) {
	// The real rule metadata too: every built-in rule must be valid SARIF.
	full := resultWithEverything()
	full.Rules = nil
	for _, r := range rules.Builtin() {
		full.Rules = append(full.Rules, r.Meta())
	}
	var buf bytes.Buffer
	if err := Write(&buf, "sarif", full, Options{Version: "test"}); err != nil {
		t.Fatal(err)
	}
	checkSARIF(t, buf.String())
	checkSARIF(t, render(t, "sarif"))
}

func checkSARIF(t *testing.T, doc string) {
	t.Helper()
	var log map[string]any
	if err := json.Unmarshal([]byte(doc), &log); err != nil {
		t.Fatal(err)
	}
	str := func(m map[string]any, k string) string { s, _ := m[k].(string); return s }
	obj := func(v any) map[string]any { m, _ := v.(map[string]any); return m }
	list := func(v any) []any { l, _ := v.([]any); return l }

	if str(log, "version") != "2.1.0" || !strings.Contains(str(log, "$schema"), "sarif-2.1.0") {
		t.Fatalf("bad version/schema: %v %v", log["version"], log["$schema"])
	}
	runs := list(log["runs"])
	if len(runs) != 1 {
		t.Fatalf("want one run, got %d", len(runs))
	}
	run := obj(runs[0])
	driver := obj(obj(run["tool"])["driver"])
	if str(driver, "name") == "" {
		t.Error("tool.driver.name is required")
	}
	ruleIDs := map[string]int{}
	for i, r := range list(driver["rules"]) {
		rule := obj(r)
		id := str(rule, "id")
		if id == "" {
			t.Errorf("rules[%d] has no id", i)
		}
		if _, dup := ruleIDs[id]; dup {
			t.Errorf("duplicate rule id %s", id)
		}
		ruleIDs[id] = i
		if lvl := str(obj(rule["defaultConfiguration"]), "level"); lvl != "error" && lvl != "warning" && lvl != "note" && lvl != "none" {
			t.Errorf("rule %s: bad default level %q", id, lvl)
		}
		if sev := str(obj(rule["properties"]), "security-severity"); !regexp.MustCompile(`^\d+(\.\d+)?$`).MatchString(sev) {
			t.Errorf("rule %s: security-severity %q is not numeric", id, sev)
		}
		if str(obj(rule["shortDescription"]), "text") == "" {
			t.Errorf("rule %s: shortDescription.text is required by GitHub", id)
		}
	}
	for i, r := range list(run["results"]) {
		res := obj(r)
		id := str(res, "ruleId")
		idx, known := ruleIDs[id]
		if !known {
			t.Errorf("results[%d]: ruleId %q is not in tool.driver.rules", i, id)
		}
		if got, _ := res["ruleIndex"].(float64); int(got) != idx {
			t.Errorf("results[%d]: ruleIndex %v does not match rule %s at %d", i, res["ruleIndex"], id, idx)
		}
		if lvl := str(res, "level"); lvl != "error" && lvl != "warning" && lvl != "note" && lvl != "none" {
			t.Errorf("results[%d]: bad level %q", i, lvl)
		}
		if str(obj(res["message"]), "text") == "" {
			t.Errorf("results[%d]: message.text is required", i)
		}
		locs := list(res["locations"])
		if len(locs) == 0 {
			t.Fatalf("results[%d]: no locations", i)
		}
		phys := obj(obj(locs[0])["physicalLocation"])
		uri := str(obj(phys["artifactLocation"]), "uri")
		if uri == "" || strings.Contains(uri, `\`) || strings.HasPrefix(uri, "/") || regexp.MustCompile(`^[A-Za-z]:`).MatchString(uri) {
			t.Errorf("results[%d]: uri %q must be a relative, slash-separated path", i, uri)
		}
		if line, _ := obj(phys["region"])["startLine"].(float64); line < 1 {
			t.Errorf("results[%d]: startLine must be >= 1, got %v", i, line)
		}
		if len(obj(res["partialFingerprints"])) == 0 {
			t.Errorf("results[%d]: partialFingerprints missing (needed to track alerts across runs)", i)
		}
	}
	invs := list(run["invocations"])
	if len(invs) != 1 {
		t.Fatalf("want one invocation, got %d", len(invs))
	}
	inv := obj(invs[0])
	if ok, present := inv["executionSuccessful"].(bool); !present || ok {
		t.Errorf("executionSuccessful = %v, want false (a file timed out)", inv["executionSuccessful"])
	}
	if n := list(inv["toolExecutionNotifications"]); len(n) != 1 || str(obj(n[0]), "level") != "warning" {
		t.Errorf("notifications = %v", n)
	}
}

func TestGitHubAnnotationsAreEscaped(t *testing.T) {
	res := resultWithEverything()
	res.Findings[0].Message = "line one\nline two, 100% bad: yes"
	res.Findings[0].File = "dir/a,b:c.py"
	var buf bytes.Buffer
	if err := Write(&buf, "github", res, Options{}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if strings.Contains(out, "line one\nline two") || !strings.Contains(out, "line one%0Aline two, 100%25 bad: yes") || !strings.Contains(out, "file=dir/a%2Cb%3Ac.py") {
		t.Errorf("workflow command not escaped:\n%s", out)
	}
}

func TestMarkdownEscapesTableCells(t *testing.T) {
	out := render(t, "markdown")
	if !strings.Contains(out, `with a pipe`) || !strings.Contains(out, `\| with a pipe`) {
		t.Errorf("pipe in a message must be escaped:\n%s", out)
	}
}

func TestSARIFURIs(t *testing.T) {
	cwd, _ := os.Getwd()
	cases := map[string]string{
		"src/a.py":                        "src/a.py",
		"./src/a.py":                      "src/a.py",
		filepath.Join(cwd, "src", "a.py"): "src/a.py",
		"/somewhere/else/b.py":            "file:///somewhere/else/b.py",
		"C:/Users/me/proj/c.py":           "file:///C:/Users/me/proj/c.py",
		`dir\sub\d.py`:                    "dir/sub/d.py",
	}
	for in, want := range cases {
		if filepath.Separator == '\\' && strings.HasPrefix(in, "/somewhere") {
			continue // a rooted path without a drive is not absolute on Windows
		}
		if got := sarifURI(in); got != want {
			t.Errorf("sarifURI(%q) = %q, want %q", in, got, want)
		}
	}
}
