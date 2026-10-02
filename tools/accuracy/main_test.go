package main

import (
	"strings"
	"testing"
)

func TestReconcile(t *testing.T) {
	r := &repo{
		Name: "x/y",
		Labels: []label{
			{Rule: "MCPG004", File: "a.py", Tool: "run", Label: "tp"},
			{Rule: "MCPG001", File: "b.py", Tool: "read", Label: "fp"},
			{Rule: "MCPG002", File: "gone.py", Label: "tp"},
			{Rule: "MCPG005", File: "c.py", Tool: "q", Label: "todo"},
		},
		KnownGaps: []gap{{Rule: "MCPG004", File: "miss.py", Tool: "exec", Why: "helper"}},
	}
	fs := []found{
		{Rule: "MCPG004", File: "a.py", Tool: "run", Line: 3},
		{Rule: "MCPG001", File: "b.py", Tool: "read", Line: 9},
		{Rule: "MCPG005", File: "c.py", Tool: "q", Line: 1},
		{Rule: "MCPG006", File: "new.py", Tool: "drop", Line: 2},
		{Rule: "MCPG004", File: "miss.py", Tool: "exec", Line: 5},
	}
	tl := tally{}
	got := strings.Join(reconcile(r, fs, tl, false), "\n")
	for _, want := range []string{"unlabelled finding MCPG006 new.py", "stale label for MCPG002", `is "todo"`, "known gap now detected"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing problem %q in:\n%s", want, got)
		}
	}
	if tl["MCPG004"].tp != 1 || tl["MCPG001"].fp != 1 {
		t.Errorf("tally = %+v %+v", tl["MCPG004"], tl["MCPG001"])
	}

	// -update drops stale labels and adds todo stubs instead of reporting problems.
	if p := reconcile(r, fs, tally{}, true); len(p) != 0 {
		t.Errorf("update returned problems: %v", p)
	}
	var todo, stale int
	for _, l := range r.Labels {
		if l.Label == "todo" && l.Rule == "MCPG006" {
			todo++
		}
		if l.Rule == "MCPG002" {
			stale++
		}
	}
	if todo != 1 || stale != 0 {
		t.Errorf("labels after update = %+v", r.Labels)
	}
}

func TestPrecisionReport(t *testing.T) {
	tl := tally{}
	for _, l := range []string{"tp", "tp", "tp", "fp"} {
		tl.add("MCPG001", l)
	}
	tl.add("MCPG002", "tp")
	_, bad := precisionReport(tl, 0.9)
	if len(bad) != 1 || !strings.Contains(bad[0], "MCPG001") || !strings.Contains(bad[0], "75%") {
		t.Errorf("failures = %v", bad)
	}
	if _, bad := precisionReport(tl, 0.5); len(bad) != 0 {
		t.Errorf("unexpected failures: %v", bad)
	}
}
