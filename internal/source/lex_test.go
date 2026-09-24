package source

import (
	"reflect"
	"testing"
)

func stmtTexts(f *File) []string {
	var out []string
	for _, s := range f.Statements(1, len(f.Lines)) {
		out = append(out, s.Text)
	}
	return out
}

func TestStatementsPython(t *testing.T) {
	f := NewFile("x.py", Python, "cmd = args['c']  # comment\nsubprocess.run(\n    cmd,\n    shell=True,\n)\nx = 1\n")
	got := stmtTexts(f)
	want := []string{"cmd = args['c']", "subprocess.run(\n    cmd,\n    shell=True,\n)", "x = 1"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q\nwant %q", got, want)
	}
	if s := f.Statements(1, 6)[1]; s.Line != 2 || s.EndLine != 5 {
		t.Errorf("lines = %d-%d, want 2-5", s.Line, s.EndLine)
	}
}

func TestStatementsTypeScriptBlocks(t *testing.T) {
	src := "async ({ path }) => {\n  const p = path; // c\n  if (p) {\n    await fs.writeFile(p, {\n      encoding: 'utf8',\n    });\n  }\n  return { ok: true };\n}"
	f := NewFile("x.ts", TypeScript, src)
	got := stmtTexts(f)
	want := []string{
		"async ({ path }) => {",
		"const p = path",
		"if (p) {",
		"await fs.writeFile(p, {\n      encoding: 'utf8',\n    })",
		"return { ok: true }",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q\nwant %q", got, want)
	}
}

func TestStatementsGoCompositeLiteral(t *testing.T) {
	src := "func h() {\n\tres := &mcp.Result{\n\t\tText: x,\n\t}\n\treturn res\n}"
	f := NewFile("x.go", Go, src)
	got := stmtTexts(f)
	want := []string{"func h() {", "res := &mcp.Result{\n\t\tText: x,\n\t}", "return res"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q\nwant %q", got, want)
	}
}

func TestParseStringLiteral(t *testing.T) {
	cases := []struct {
		lang Language
		in   string
		want string
	}{
		{Python, `  "a" 'b'`, "ab"},
		{Python, `("abc "` + "\n" + `  "def")`, "abc def"},
		{Python, `r"\d+"`, `\d+`},
		{Python, `"""multi` + "\n" + `line"""`, "multi\nline"},
		{TypeScript, `"a" + 'b' + ` + "`c`", "abc"},
		{TypeScript, `"zero` + string(rune(92)) + `u200bwidth"`, "zero" + string(rune(0x200b)) + "width"},              // JS escape decoded
		{TypeScript, `"tag` + string(rune(92)) + `uDB40` + string(rune(92)) + `uDC41"`, "tag" + string(rune(0xE0041))}, // surrogate pair
		{Go, "`raw\\n`", `raw\n`},
		{Go, `"x\ty"`, "x\ty"},
	}
	for _, c := range cases {
		got, _, ok := ParseStringLiteral(c.in, 0, c.lang)
		if !ok || got != c.want {
			t.Errorf("ParseStringLiteral(%s, %q) = %q, %v; want %q", c.lang, c.in, got, ok, c.want)
		}
	}
}

func TestIdentIndex(t *testing.T) {
	cases := []struct {
		text, name string
		want       bool
	}{
		{"open(path)", "path", true},
		{"os.path.join(a)", "path", false},
		{"filepath", "path", false},
		{"f'{cmd} x'", "cmd", true},
		{"${cmd}", "cmd", true},
		{"cmd_line", "cmd", false},
	}
	for _, c := range cases {
		if got := ContainsIdent(c.text, c.name); got != c.want {
			t.Errorf("ContainsIdent(%q, %q) = %v", c.text, c.name, got)
		}
	}
}
