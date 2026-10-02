package finding

import (
	"encoding/json"
	"testing"
)

func TestParseSeverity(t *testing.T) {
	for i, name := range []string{"info", "LOW", " Medium ", "high", "critical"} {
		got, err := ParseSeverity(name)
		if err != nil || got != Severity(i) {
			t.Errorf("ParseSeverity(%q) = %v, %v", name, got, err)
		}
	}
	if _, err := ParseSeverity("severe"); err == nil {
		t.Error("expected an error for an unknown severity")
	}
	if s := Severity(42).String(); s != "severity(42)" {
		t.Errorf("out-of-range String() = %q", s)
	}
}

func TestSeverityTextRoundTrip(t *testing.T) {
	b, err := json.Marshal(struct{ S Severity }{High})
	if err != nil || string(b) != `{"S":"high"}` {
		t.Fatalf("marshal = %s, %v", b, err)
	}
	var v struct{ S Severity }
	if err := json.Unmarshal([]byte(`{"S":"critical"}`), &v); err != nil || v.S != Critical {
		t.Fatalf("unmarshal = %v, %v", v.S, err)
	}
	if err := json.Unmarshal([]byte(`{"S":"nope"}`), &v); err == nil {
		t.Error("expected an error for an unknown severity")
	}
}

func TestFingerprintIgnoresLineNumbers(t *testing.T) {
	a := Finding{RuleID: "MCPG004", File: "s.py", Line: 10, Tool: "run", Snippet: " os.system(cmd) ", Message: "m"}
	b := a
	b.Line = 99
	b.Snippet = "os.system(cmd)"
	a.ComputeFingerprint()
	b.ComputeFingerprint()
	if a.Fingerprint == "" || a.Fingerprint != b.Fingerprint {
		t.Errorf("fingerprints differ: %q vs %q", a.Fingerprint, b.Fingerprint)
	}
	c := a
	c.RuleID = "MCPG001"
	c.ComputeFingerprint()
	if c.Fingerprint == a.Fingerprint {
		t.Error("different rules must not share a fingerprint")
	}
}

func TestSortAndCount(t *testing.T) {
	fs := []Finding{
		{RuleID: "B", Severity: Low, File: "a", Line: 1},
		{RuleID: "A", Severity: Critical, File: "b", Line: 5},
		{RuleID: "A", Severity: Critical, File: "a", Line: 9},
		{RuleID: "C", Severity: Critical, File: "a", Line: 9},
		{RuleID: "A", Severity: Critical, File: "a", Line: 2},
	}
	Sort(fs)
	want := []string{"a:2:A", "a:9:A", "a:9:C", "b:5:A", "a:1:B"}
	for i, f := range fs {
		if got := f.File + ":" + string(rune('0'+f.Line)) + ":" + f.RuleID; got != want[i] {
			t.Errorf("position %d = %s, want %s", i, got, want[i])
		}
	}
	counts := CountBySeverity(fs)
	if counts["critical"] != 4 || counts["low"] != 1 || counts["info"] != 0 || len(counts) != 5 {
		t.Errorf("counts = %v", counts)
	}
}

func TestNumberDuplicatesGivesRepeatedFindingsDistinctFingerprints(t *testing.T) {
	mk := func(snippet string) Finding {
		f := Finding{RuleID: "MCPG004", File: "a.py", Tool: "run", Snippet: snippet, Message: "m"}
		f.ComputeFingerprint()
		return f
	}
	fs := []Finding{mk("os.system(a)"), mk("os.system(a)"), mk("other()"), mk("os.system(a)")}
	first := fs[0].Fingerprint
	NumberDuplicates(fs)
	if fs[0].Fingerprint != first {
		t.Error("the first occurrence must keep its fingerprint (stable baselines)")
	}
	seen := map[string]bool{}
	for _, f := range fs {
		if seen[f.Fingerprint] {
			t.Errorf("duplicate fingerprint %s", f.Fingerprint)
		}
		seen[f.Fingerprint] = true
	}
	if len(seen) != 4 {
		t.Errorf("distinct = %d", len(seen))
	}
	again := []Finding{mk("os.system(a)"), mk("os.system(a)")}
	NumberDuplicates(again)
	if again[1].Fingerprint != fs[1].Fingerprint {
		t.Error("occurrence fingerprints must be deterministic")
	}
}
