package rules

import (
	"strings"
	"testing"

	"github.com/Gerijacki/mcp-guard/internal/extract"
	"github.com/Gerijacki/mcp-guard/internal/source"
)

func checkWith(t *testing.T, id string, ext Extension, name, src string) int {
	t.Helper()
	rs, err := WithExtensions(Builtin(), map[string]Extension{id: ext})
	if err != nil {
		t.Fatal(err)
	}
	f := source.NewFile(name, source.DetectLanguage(name), src)
	extract.Extract(f)
	n := 0
	for _, r := range rs {
		if r.Meta().ID == id {
			n += len(r.Check(f))
		}
	}
	return n
}

const extPy = `from mcp.server.fastmcp import FastMCP

mcp = FastMCP("x")


@mcp.tool()
def read_it(path: str) -> str:
    """Read."""
    clean = confine(path)
    return storage.read(clean)


@mcp.tool()
def read_other(name: str) -> str:
    """Read."""
    return storage.read(name)
`

func TestExtendSinksAndSanitizers(t *testing.T) {
	// Without extensions neither tool is reported: storage.read is unknown.
	if n := checkWith(t, "MCPG001", Extension{}, "s.py", extPy); n != 0 {
		t.Fatalf("baseline findings = %d", n)
	}
	// A custom sink makes both tools reachable...
	sink := Extension{Sinks: []string{`\bstorage\.read\s*\(`}}
	if n := checkWith(t, "MCPG001", sink, "s.py", extPy); n != 2 {
		t.Errorf("with the sink: %d findings, want 2", n)
	}
	// ...and a custom sanitizer clears the one that goes through safe_join.
	both := Extension{Sinks: sink.Sinks, Sanitizers: []string{`\bconfine\s*\(`}}
	if n := checkWith(t, "MCPG001", both, "s.py", extPy); n != 1 {
		t.Errorf("with sink and sanitizer: %d findings, want 1 (only read_other)", n)
	}
}

func TestExtendOtherRules(t *testing.T) {
	sh := "from mcp.server.fastmcp import FastMCP\nmcp = FastMCP('x')\n\n@mcp.tool()\ndef run(cmd: str) -> str:\n    \"\"\"Run.\"\"\"\n    return run_remote(cmd)\n"
	if n := checkWith(t, "MCPG004", Extension{Sinks: []string{`\brun_remote\s*\(`}}, "s.py", sh); n != 1 {
		t.Errorf("MCPG004 custom sink: %d", n)
	}
	q := "from mcp.server.fastmcp import FastMCP\nmcp = FastMCP('x')\n\n@mcp.tool()\ndef q(name: str) -> str:\n    \"\"\"Q.\"\"\"\n    return warehouse.run_sql(f\"SELECT * FROM t WHERE n = '{name}'\")\n"
	if n := checkWith(t, "MCPG005", Extension{Sinks: []string{`\.run_sql\s*\(`}}, "s.py", q); n != 1 {
		t.Errorf("MCPG005 custom sink: %d", n)
	}
	h := "from mcp.server.fastmcp import FastMCP\nmcp = FastMCP('x')\n\n@mcp.tool()\ndef g(u: str) -> str:\n    \"\"\"G.\"\"\"\n    return net.fetch(u)\n"
	if n := checkWith(t, "MCPG009", Extension{Sinks: []string{`\bnet\.fetch\s*\(`}}, "s.py", h); n != 1 {
		t.Errorf("MCPG009 custom sink: %d", n)
	}
	if n := checkWith(t, "MCPG009", Extension{Sinks: []string{`\bnet\.fetch\s*\(`}, Sanitizers: []string{`\bcheck_host\s*\(`}}, "s.py", strings.Replace(h, "    return", "    check_host(u)\n    return", 1)); n != 0 {
		t.Errorf("MCPG009 custom sanitizer: %d", n)
	}
	d := "from mcp.server.fastmcp import FastMCP\nmcp = FastMCP('x')\n\n@mcp.tool()\ndef l(blob: str) -> str:\n    \"\"\"L.\"\"\"\n    return fancy.load(blob)\n"
	if n := checkWith(t, "MCPG010", Extension{Sinks: []string{`\bfancy\.load\s*\(`}}, "s.py", d); n != 1 {
		t.Errorf("MCPG010 custom sink: %d", n)
	}
}

func TestExtendValidation(t *testing.T) {
	cases := map[string]struct {
		id  string
		ext Extension
		msg string
	}{
		"unsupported rule":    {"MCPG006", Extension{Sinks: []string{`x\(`}}, "cannot be extended"},
		"bad regex":           {"MCPG001", Extension{Sinks: []string{`(`}}, "sink"},
		"sink must open call": {"MCPG001", Extension{Sinks: []string{`storage\.read`}}, "opening parenthesis"},
		"bad sanitizer regex": {"MCPG004", Extension{Sanitizers: []string{`[`}}, "sanitizer"},
		"MCPG012 sinks":       {"MCPG012", Extension{Sinks: []string{`x\(`}}, "not supported"},
	}
	for name, c := range cases {
		_, err := WithExtensions(Builtin(), map[string]Extension{c.id: c.ext})
		if err == nil || !strings.Contains(err.Error(), c.msg) {
			t.Errorf("%s: err = %v, want it to contain %q", name, err, c.msg)
		}
	}
}
