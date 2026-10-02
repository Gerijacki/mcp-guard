package rules

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Gerijacki/mcp-guard/internal/extract"
	"github.com/Gerijacki/mcp-guard/internal/finding"
	"github.com/Gerijacki/mcp-guard/internal/source"
)

const customPy = `from mcp.server.fastmcp import FastMCP

mcp = FastMCP("x")


@mcp.tool()
def delete_user(user_id: str) -> str:
    """Delete a user. Reviewed: SEC-12"""
    audit_log("delete", user_id)
    admin_api.call(user_id)
    return "ok"


@mcp.tool()
def list_users(prefix: str) -> str:
    """List users."""
    safe = sanitize(prefix)
    admin_api.call(safe)
    return "ok"
`

func runCustom(t *testing.T, spec CustomSpec, name, src string) []finding.Finding {
	t.Helper()
	r, err := CompileCustom(spec)
	if err != nil {
		t.Fatalf("CompileCustom: %v", err)
	}
	f := source.NewFile(name, source.DetectLanguage(name), src)
	extract.Extract(f)
	return r.Check(f)
}

func lines(fs []finding.Finding) []int {
	var out []int
	for _, f := range fs {
		out = append(out, f.Line)
	}
	return out
}

func TestCustomScopes(t *testing.T) {
	cases := []struct {
		name string
		spec CustomSpec
		file string
		src  string
		want []int
		msg  string
	}{
		{"file scope matches lines", CustomSpec{ID: "ACME001", Pattern: `admin_api`, Message: "x"}, "s.py", customPy, []int{10, 18}, ""},
		{"languages filter", CustomSpec{ID: "ACME001", Pattern: `admin_api`, Languages: []string{"go"}}, "s.py", customPy, nil, ""},
		{"tool-body with taint and param", CustomSpec{ID: "ACME002", Scope: "tool-body", Pattern: `admin_api\.call`, RequiresTaintedInput: true, Message: "{tool}/{param}"}, "s.py", customPy, []int{10, 18}, "delete_user/user_id"},
		{"sanitizers clear taint", CustomSpec{ID: "ACME002", Scope: "tool-body", Pattern: `admin_api\.call`, RequiresTaintedInput: true, Sanitizers: []string{`sanitize\(`}}, "s.py", customPy, []int{10}, ""},
		{"tools name filter", CustomSpec{ID: "ACME002", Scope: "tool-body", Pattern: `admin_api`, Tools: `^list_`}, "s.py", customPy, []int{18}, ""},
		{"unless skips matches", CustomSpec{ID: "ACME003", Scope: "tool-description", Pattern: `^`, Unless: []string{`Reviewed: SEC-\d+`}, Message: "{tool}"}, "s.py", customPy, []int{16}, "list_users"},
		{"tool-name", CustomSpec{ID: "ACME004", Scope: "tool-name", Pattern: `^delete_`, Message: "{tool}"}, "s.py", customPy, []int{6}, "delete_user"},
		{"tool-body-absent", CustomSpec{ID: "ACME005", Scope: "tool-body-absent", Pattern: `audit_log\(`, Message: "{tool} never audits"}, "s.py", customPy, []int{14}, "list_users never audits"},
		{"config-server", CustomSpec{ID: "ACME006", Scope: "config-server", Pattern: `-y\s`, Message: "{tool} auto-installs"}, "mcp.json", `{"mcpServers":{"db":{"command":"npx","args":["-y","some-pkg"]},"ok":{"command":"node","args":["s.js"]}}}`, []int{1}, "db auto-installs"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := runCustom(t, c.spec, c.file, c.src)
			if g := lines(got); !reflect.DeepEqual(g, c.want) && (len(g) != 0 || len(c.want) != 0) {
				t.Fatalf("lines = %v, want %v\n%s", g, c.want, describe(got))
			}
			if c.msg != "" && len(got) > 0 && got[0].Message != c.msg {
				t.Errorf("message = %q, want %q", got[0].Message, c.msg)
			}
		})
	}
}

func TestCompileCustomValidation(t *testing.T) {
	bad := map[string]CustomSpec{
		"bad scope":                  {ID: "ACME001", Pattern: "x", Scope: "nowhere"},
		"sanitizers need taint":      {ID: "ACME001", Pattern: "x", Scope: "tool-body", Sanitizers: []string{"y"}},
		"bad sanitizer regex":        {ID: "ACME001", Pattern: "x", Scope: "tool-body", RequiresTaintedInput: true, Sanitizers: []string{"("}},
		"tools needs a tool scope":   {ID: "ACME001", Pattern: "x", Tools: "a"},
		"bad tools regex":            {ID: "ACME001", Pattern: "x", Scope: "tool-name", Tools: "("},
		"bad severity":               {ID: "ACME001", Pattern: "x", Severity: "extreme"},
		"bad unless regex":           {ID: "ACME001", Pattern: "x", Unless: []string{"("}},
		"pattern required":           {ID: "ACME001"},
		"reserved prefix":            {ID: "MCPG100", Pattern: "x"},
		"tainted input needs a body": {ID: "ACME001", Pattern: "x", Scope: "file", RequiresTaintedInput: true},
	}
	for name, spec := range bad {
		if _, err := CompileCustom(spec); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	r, err := CompileCustom(CustomSpec{ID: "ACME001", Pattern: "x", Description: "First line.\nSecond line."})
	if err != nil {
		t.Fatal(err)
	}
	if m := r.Meta(); m.Name != "acme001" || m.Summary != "First line." || m.Severity != finding.Medium {
		t.Errorf("defaults: %+v", m)
	}
}

func TestLoadCustomFileAndDirectory(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	one := write("one.yml", "rules:\n  - id: ACME001\n    pattern: foo\n  - id: ACME002\n    pattern: bar\n")
	write("sub/two.yaml", "rules:\n  - id: ACME003\n    pattern: baz\n")
	write("sub/ignored.txt", "not yaml")

	rs, err := LoadCustom(one)
	if err != nil || len(rs) != 2 {
		t.Fatalf("file: %v %d", err, len(rs))
	}
	rs, err = LoadCustom(dir)
	if err != nil || len(rs) != 3 {
		t.Fatalf("directory: %v %d", err, len(rs))
	}

	if _, err := LoadCustom(filepath.Join(dir, "missing.yml")); err == nil {
		t.Error("missing file should fail")
	}
	bad := write("bad.yml", "rules: [")
	if _, err := LoadCustom(bad); err == nil || !strings.Contains(err.Error(), "bad.yml") {
		t.Errorf("invalid YAML: %v", err)
	}
	os.Remove(bad)
	write("invalid.yml", "rules:\n  - id: lower\n    pattern: x\n")
	if _, err := LoadCustom(dir); err == nil || !strings.Contains(err.Error(), "rule #1") {
		t.Errorf("invalid rule should name file and position: %v", err)
	}
}
