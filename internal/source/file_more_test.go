package source

import (
	"strings"
	"testing"
)

func TestMaskStringsKeepsOffsetsAndCode(t *testing.T) {
	cases := []struct {
		lang Language
		in   string
		want string
	}{
		{Python, `x = "secret" + 'a b'  # "kept"`, `x = "      " + '   '  # "kept"`},
		{Python, "d = '''doc\nline'''\ny = 1", "d = '     \n      '\ny = 1"},
		{TypeScript, "const s = `t ${x} u`; f(\"a\")", "const s = `        `; f(\" \")"},
		{Go, "s := `raw \"quoted\"`\nt := \"é\"", "s := `            `\nt := \"  \""},
		{Python, `x = ""`, `x = ""`},
	}
	for _, c := range cases {
		got := MaskStrings(c.in, c.lang)
		if len(got) != len(c.in) {
			t.Errorf("length changed for %q: %d -> %d", c.in, len(c.in), len(got))
		}
		if got != c.want {
			t.Errorf("MaskStrings(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestSkeletonHidesRegistrationsInsideStrings(t *testing.T) {
	src := "def f():\n    \"\"\"Example:\n\n    @mcp.tool()\n    def doc_tool(): ...\n    \"\"\"\n\n@mcp.tool()\ndef real(): ...\n"
	f := NewFile("x.py", Python, src)
	sk := f.Skeleton()
	if strings.Count(sk, "@mcp.tool()") != 1 || !strings.Contains(sk, "def real") {
		t.Errorf("skeleton keeps the docstring example:\n%s", sk)
	}
	if f.Skeleton() != sk || len(sk) != len(src) {
		t.Error("skeleton must be cached and keep offsets")
	}
}

func TestInComment(t *testing.T) {
	f := NewFile("x.py", Python, "a = 1  # mcp-guard:ignore\nb = \"# mcp-guard:ignore\"\n")
	i := strings.Index(f.Lines[0], "mcp-guard")
	if !f.InComment(1, i, i+len("mcp-guard:ignore")) {
		t.Error("marker in a comment must count")
	}
	j := strings.Index(f.Lines[1], "mcp-guard")
	if f.InComment(2, j, j+len("mcp-guard:ignore")) {
		t.Error("marker inside a string literal must not count")
	}
	if f.InComment(1, -1, 3) || f.InComment(1, 5, 5) || f.InComment(9, 0, 3) {
		t.Error("out-of-range spans are not comments")
	}
}

func TestCodeTextDropsCommentsDocstringAndAddsGuards(t *testing.T) {
	src := "@mcp.tool()\ndef f(p):\n    \"\"\"validates the path against ALLOWED\"\"\"\n    # also checks safe_join\n    return open(p)\n"
	f := NewFile("x.py", Python, src)
	tool := Tool{Name: "f", BodyFrom: strings.Index(src, "    \"\"\""), BodyTo: len(src)}
	text := f.CodeText(tool)
	if strings.Contains(text, "ALLOWED") || strings.Contains(text, "safe_join") || !strings.Contains(text, "open(p)") {
		t.Errorf("CodeText = %q", text)
	}
	tool.Guards = []string{"caller_check(p)"}
	if got := f.CodeText(tool); !strings.HasPrefix(got, "caller_check(p)\n") {
		t.Errorf("guards must be prepended: %q", got)
	}
}

func TestToolStatementsAreCachedAndNounNames(t *testing.T) {
	src := "def f(p):\n    a = p\n    b = a\n"
	f := NewFile("x.py", Python, src)
	tool := Tool{BodyFrom: strings.Index(src, "    a"), BodyTo: len(src)}
	first, second := f.ToolStatements(tool), f.ToolStatements(tool)
	if len(first) != 2 || &first[0] != &second[0] {
		t.Errorf("statements not cached: %v", first)
	}
	if first[0].Indent != 4 || first[1].Indent != 4 {
		t.Errorf("indent = %d, %d", first[0].Indent, first[1].Indent)
	}
	for kind, want := range map[string]string{"": "Tool", "resource": "Resource", "prompt": "Prompt"} {
		if got := (Tool{Kind: kind}).Noun(); got != want {
			t.Errorf("Noun(%q) = %q", kind, got)
		}
	}
	if got := Identifiers("os.path.join(a_b, $c, 9x)"); strings.Join(got, ",") != "os,path,join,a_b,$c,x" {
		t.Errorf("Identifiers = %v", got)
	}
}

func TestMaskMultilineStrings(t *testing.T) {
	in := "x = \"keep\"\ndoc = '''api_key = \"abc\"\nmore'''\ny = 'z'  # note\n"
	got := MaskMultilineStrings(in, Python)
	if len(got) != len(in) || !strings.Contains(got, `x = "keep"`) || !strings.Contains(got, "y = 'z'") || strings.Contains(got, "api_key") {
		t.Errorf("MaskMultilineStrings = %q", got)
	}
	if got := MaskMultilineStrings("a = `one\ntwo`\n", TypeScript); strings.Contains(got, "one") {
		t.Errorf("template literal spanning lines not masked: %q", got)
	}
	if s := "plain = 1\n"; MaskMultilineStrings(s, Go) != s {
		t.Error("text without strings must be returned unchanged")
	}
}
