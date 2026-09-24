package source

import (
	"strings"
	"testing"
)

func TestDetectLanguage(t *testing.T) {
	cases := map[string]Language{
		"server.py": Python, "index.ts": TypeScript, "app.MJS": TypeScript, "view.tsx": TypeScript,
		"main.go": Go, "mcp.json": JSON, "settings.jsonc": JSON, "ci.yml": YAML, "pyproject.toml": TOML,
		".env": Env, ".env.local": Env, "prod.env": Env,
		"bundle.min.js": Unknown, "types.d.ts": Unknown, "README.md": Unknown, "Makefile": Unknown,
	}
	for path, want := range cases {
		if got := DetectLanguage(path); got != want {
			t.Errorf("DetectLanguage(%q) = %q, want %q", path, got, want)
		}
	}
	if !Python.IsCode() || JSON.IsCode() {
		t.Error("IsCode mismatch")
	}
}

func TestParseLanguage(t *testing.T) {
	for in, want := range map[string]Language{"py": Python, "JavaScript": TypeScript, "golang": Go, "yml": YAML, "dotenv": Env, "json": JSON, "toml": TOML} {
		if got, ok := ParseLanguage(in); !ok || got != want {
			t.Errorf("ParseLanguage(%q) = %q, %v", in, got, ok)
		}
	}
	if _, ok := ParseLanguage("cobol"); ok {
		t.Error("cobol should be unknown")
	}
}

func TestLinesAndOffsets(t *testing.T) {
	f := NewFile("x.py", Python, "a = 1\r\nb = 2\n\nc = 3")
	if len(f.Lines) != 4 || f.Line(2) != "b = 2" || f.Line(0) != "" || f.Line(9) != "" {
		t.Fatalf("lines = %q", f.Lines)
	}
	if strings.Contains(f.Content, "\r") {
		t.Error("CRLF not normalized")
	}
	if got := f.LineAt(strings.Index(f.Content, "c")); got != 4 {
		t.Errorf("LineAt = %d", got)
	}
	if f.LineStart(0) != 0 || f.LineStart(99) != len(f.Content) || f.LineEnd(1) != 5 || f.LineEnd(99) != len(f.Content) {
		t.Error("LineStart/LineEnd bounds")
	}
	if f.FindLine("c = 3", 1) != 4 || f.FindLine("missing", 2) != 2 {
		t.Error("FindLine")
	}
}

func TestToolBody(t *testing.T) {
	f := NewFile("x.py", Python, "def f(x):\n    y = x\n    return y\n")
	var tool Tool
	if tool.HasBody() || f.BodyText(tool) != "" || f.ToolStatements(tool) != nil {
		t.Error("empty tool should have no body")
	}
	f.SetBody(&tool, f.LineStart(2), f.LineEnd(3))
	if !tool.HasBody() || tool.BodyStart != 2 || tool.BodyEnd != 3 {
		t.Fatalf("tool = %+v", tool)
	}
	if got := f.BodyText(tool); got != "    y = x\n    return y" {
		t.Errorf("BodyText = %q", got)
	}
	if st := f.ToolStatements(tool); len(st) != 2 || st[1].Text != "return y" || st[1].Line != 3 {
		t.Errorf("statements = %+v", st)
	}
	f.SetBody(&tool, 10, 5) // inverted range is ignored
	if tool.BodyStart != 2 {
		t.Error("inverted range changed the body")
	}
	tool.Annotations = map[string]string{"destructivehint": "true"}
	if tool.Hint("destructiveHint") != "true" || tool.Hint("readOnlyHint") != "" {
		t.Error("Hint lookup is not case-insensitive")
	}
}

func TestCodeMasksComments(t *testing.T) {
	f := NewFile("x.ts", TypeScript, "a(1) // server.tool(\"x\")\nconst s = \"// not a comment\"")
	code := f.Code()
	if len(code) != len(f.Content) || strings.Contains(code, "server.tool") || !strings.Contains(code, "// not a comment") {
		t.Errorf("Code() = %q", code)
	}
	if f.Code() != code {
		t.Error("Code() should be stable")
	}
}

func TestMatchCloseAndSplitArgs(t *testing.T) {
	s := `f(a, "x)", g(b, c), [1, 2]) tail`
	close := MatchClose(s, 1, TypeScript)
	if close != strings.Index(s, " tail")-1 {
		t.Fatalf("MatchClose = %d", close)
	}
	var args []string
	for _, seg := range SplitArgs(s, 2, close, TypeScript) {
		args = append(args, seg.Text(s))
	}
	if strings.Join(args, "|") != `a|"x)"|g(b, c)|[1, 2]` {
		t.Errorf("SplitArgs = %q", args)
	}
	if MatchClose("f(a", 1, Go) != -1 {
		t.Error("unbalanced input should return -1")
	}
	if SkipSpace(" \n\tx", 0) != 3 {
		t.Error("SkipSpace")
	}
	if Indent("\t  x") != 6 {
		t.Error("Indent")
	}
}
