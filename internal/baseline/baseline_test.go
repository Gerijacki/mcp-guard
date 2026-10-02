package baseline

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Gerijacki/mcp-guard/internal/finding"
)

func fd(rule, file, fp string) finding.Finding {
	return finding.Finding{RuleID: rule, File: file, Fingerprint: fp, Message: "m"}
}

func TestSaveLoadFilter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "baseline.json")
	old := []finding.Finding{fd("MCPG004", "b.py", "bbb"), fd("MCPG001", "a.py", "aaa"), fd("MCPG005", "c.py", "ccc")}
	if err := Save(path, old); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	if strings.Index(string(raw), "a.py") > strings.Index(string(raw), "b.py") {
		t.Errorf("entries are not sorted by file:\n%s", raw)
	}
	b, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	now := []finding.Finding{fd("MCPG004", "b.py", "bbb"), fd("MCPG001", "a.py", "aaa"), fd("MCPG009", "d.py", "ddd")}
	kept, hidden, gone := b.Filter(now)
	if len(kept) != 1 || kept[0].Fingerprint != "ddd" || hidden != 2 || gone != 1 {
		t.Errorf("kept=%v hidden=%d gone=%d", kept, hidden, gone)
	}
}

func TestLoadErrors(t *testing.T) {
	dir := t.TempDir()
	if _, err := Load(filepath.Join(dir, "missing.json")); err == nil {
		t.Error("missing file should fail")
	}
	bad := filepath.Join(dir, "bad.json")
	os.WriteFile(bad, []byte("{"), 0o644)
	if _, err := Load(bad); err == nil {
		t.Error("invalid JSON should fail")
	}
	v2 := filepath.Join(dir, "v2.json")
	os.WriteFile(v2, []byte(`{"version":2,"findings":[]}`), 0o644)
	if _, err := Load(v2); err == nil || !strings.Contains(err.Error(), "version") {
		t.Errorf("wrong version: %v", err)
	}
}
