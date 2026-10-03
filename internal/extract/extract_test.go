package extract

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Gerijacki/mcp-guard/internal/source"
)

func load(t *testing.T, name string) *source.File {
	t.Helper()
	path := filepath.Join("..", "..", "testdata", "extract", name)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	f := source.NewFile(name, source.DetectLanguage(path), string(b))
	Extract(f)
	return f
}

func toolByName(t *testing.T, f *source.File, name string) source.Tool {
	t.Helper()
	for _, tool := range f.Tools {
		if tool.Name == name {
			return tool
		}
	}
	var names []string
	for _, tool := range f.Tools {
		names = append(names, tool.Name)
	}
	t.Fatalf("%s: tool %q not found; got %v", f.Path, name, names)
	return source.Tool{}
}

// bodyContains asserts that the tool's handler body includes the given snippet.
func bodyContains(t *testing.T, f *source.File, tool source.Tool, snippet string) {
	t.Helper()
	if !tool.HasBody() {
		t.Fatalf("%s: tool %q has no body", f.Path, tool.Name)
	}
	if body := f.BodyText(tool); !strings.Contains(body, snippet) {
		t.Fatalf("%s: tool %q body (lines %d-%d) does not contain %q:\n%s", f.Path, tool.Name, tool.BodyStart, tool.BodyEnd, snippet, body)
	}
}

func TestPythonFastMCP(t *testing.T) {
	f := load(t, "fastmcp_server.py")

	read := toolByName(t, f, "read_file")
	if !reflect.DeepEqual(read.Params, []string{"path"}) {
		t.Errorf("read_file params = %v, want [path] (ctx must be skipped)", read.Params)
	}
	if !strings.HasPrefix(read.Description, "Read a text file.") {
		t.Errorf("read_file description = %q", read.Description)
	}
	bodyContains(t, f, read, "open(path)")

	del := toolByName(t, f, "delete_file")
	if del.Description != "Delete a file from disk" || del.Hint("destructiveHint") != "true" {
		t.Errorf("delete_file = %+v", del)
	}
	if !reflect.DeepEqual(del.Params, []string{"target"}) {
		t.Errorf("delete_file params = %v", del.Params)
	}
	if !reflect.DeepEqual(del.ParamDescriptions, []string{"File to delete"}) {
		t.Errorf("delete_file param descriptions = %v", del.ParamDescriptions)
	}
	bodyContains(t, f, del, "os.remove(target)")

	ping := toolByName(t, f, "ping")
	bodyContains(t, f, ping, `return "pong"`)

	sum := toolByName(t, f, "summarize_text")
	if !reflect.DeepEqual(sum.Params, []string{"text", "max_words"}) {
		t.Errorf("summarize_text params = %v", sum.Params)
	}
}

func TestPythonLowLevel(t *testing.T) {
	f := load(t, "lowlevel_server.py")
	run := toolByName(t, f, "run")
	if run.Description != "Run a command" || run.HasBody() {
		t.Errorf("run = %+v", run)
	}
	disp := toolByName(t, f, "call_tool")
	if !disp.Dispatcher || !reflect.DeepEqual(disp.Params, []string{"arguments"}) {
		t.Errorf("call_tool = %+v", disp)
	}
	bodyContains(t, f, disp, `arguments["cmd"]`)
}

func TestTypeScript(t *testing.T) {
	f := load(t, "server.ts")

	read := toolByName(t, f, "read_file")
	if read.Description != "Read a file from disk" || !reflect.DeepEqual(read.Params, []string{"path"}) {
		t.Errorf("read_file = %+v", read)
	}
	if !reflect.DeepEqual(read.ParamDescriptions, []string{"Path of the file"}) {
		t.Errorf("read_file param descriptions = %v", read.ParamDescriptions)
	}
	bodyContains(t, f, read, "fs.readFile(path")

	del := toolByName(t, f, "delete_file")
	if del.Description != "Delete a file" || del.Hint("destructiveHint") != "true" {
		t.Errorf("delete_file = %+v", del)
	}
	if !reflect.DeepEqual(del.Params, []string{"filePath"}) {
		t.Errorf("delete_file params = %v, want [filePath] (renamed destructuring)", del.Params)
	}
	bodyContains(t, f, del, "fs.unlink(filePath)")

	echo := toolByName(t, f, "echo")
	if !reflect.DeepEqual(echo.Params, []string{"args"}) {
		t.Errorf("echo params = %v", echo.Params)
	}
	bodyContains(t, f, echo, "args.msg")

	search := toolByName(t, f, "search")
	if search.Description != "Search the web" || search.HasBody() {
		t.Errorf("search = %+v", search)
	}

	disp := toolByName(t, f, "CallToolRequestSchema handler")
	if !disp.Dispatcher || !reflect.DeepEqual(disp.Params, []string{"request"}) {
		t.Errorf("dispatcher = %+v", disp)
	}
	bodyContains(t, f, disp, "request.params.arguments")
}

func TestGoMark3labs(t *testing.T) {
	f := load(t, "server.go")

	read := toolByName(t, f, "read_file")
	if read.Description != "Read a file" || read.Hint("readOnlyHint") != "true" {
		t.Errorf("read_file = %+v", read)
	}
	if !reflect.DeepEqual(read.Params, []string{"request"}) {
		t.Errorf("read_file params = %v", read.Params)
	}
	if !reflect.DeepEqual(read.ParamDescriptions, []string{"Path to read"}) {
		t.Errorf("read_file param descriptions = %v", read.ParamDescriptions)
	}
	bodyContains(t, f, read, "os.ReadFile(path)")

	del := toolByName(t, f, "delete_file")
	if del.Hint("destructiveHint") != "true" || !reflect.DeepEqual(del.Params, []string{"req"}) {
		t.Errorf("delete_file = %+v", del)
	}
	bodyContains(t, f, del, "os.Remove(p)")
	if len(f.Tools) != 2 {
		t.Errorf("got %d tools, want 2 (definitions must not be duplicated)", len(f.Tools))
	}
}

func TestGoOfficialSDK(t *testing.T) {
	f := load(t, "gosdk_server.go")
	greet := toolByName(t, f, "greet")
	if greet.Description != "Say hi" || !reflect.DeepEqual(greet.Params, []string{"req", "args"}) {
		t.Errorf("greet = %+v", greet)
	}
	bodyContains(t, f, greet, "args.Name")
}

func TestConfig(t *testing.T) {
	f := load(t, "claude_desktop_config.json")
	if !f.IsMCPConfig || len(f.Servers) != 2 {
		t.Fatalf("config = %+v", f.Servers)
	}
	gh := f.Servers[1]
	if gh.Name != "github" || gh.Command != "docker" || gh.Env["GITHUB_PERSONAL_ACCESS_TOKEN"] != "${GITHUB_TOKEN}" || gh.Line != 7 {
		t.Errorf("github server = %+v", gh)
	}
}

func TestNotAConfig(t *testing.T) {
	f := source.NewFile("package.json", source.JSON, `{"name": "x", "servers": ["a"]}`)
	Extract(f)
	if f.IsMCPConfig {
		t.Error("package.json detected as MCP config")
	}
}

func TestCommentedOutToolsAreIgnored(t *testing.T) {
	cases := map[string]string{
		"x.go": "package main\n// s.AddTool(mcp.NewTool(\"old\"), h)\n/* mcp.NewTool(\"older\") */\n",
		"x.ts": "// server.tool(\"old\", \"desc\", {}, async () => {})\n",
		"x.py": "# @mcp.tool()\n# def old(x): pass\n",
	}
	for name, src := range cases {
		f := source.NewFile(name, source.DetectLanguage(name), src)
		Extract(f)
		if len(f.Tools) != 0 {
			t.Errorf("%s: extracted tools from comments: %+v", name, f.Tools)
		}
	}
}

func TestPythonResourcesPromptsAndVariants(t *testing.T) {
	f := load(t, "primitives.py")
	note := toolByName(t, f, "read_note")
	if note.Kind != "resource" || !reflect.DeepEqual(note.Params, []string{"path"}) {
		t.Errorf("resource = %+v", note)
	}
	bodyContains(t, f, note, "open(path)")
	if p := toolByName(t, f, "review"); p.Kind != "prompt" || p.Noun() != "Prompt" {
		t.Errorf("prompt = %+v", p)
	}
	bare := toolByName(t, f, "bare")
	if bare.Kind != "" || bare.Noun() != "Tool" || !strings.HasPrefix(bare.Description, "A tool registered") {
		t.Errorf("bare @tool = %+v", bare)
	}
	bodyContains(t, f, bare, "os.popen")
	fromFn := toolByName(t, f, "from_fn")
	bodyContains(t, f, fromFn, "return q")
}

func TestTypeScriptResourcesPromptsAndAddTool(t *testing.T) {
	f := load(t, "primitives.ts")
	note := toolByName(t, f, "note")
	if note.Kind != "resource" || note.Description != "" || !reflect.DeepEqual(note.Params, []string{"uri", "id"}) {
		t.Errorf("resource = %+v", note)
	}
	prompt := toolByName(t, f, "review")
	if prompt.Kind != "prompt" || prompt.Description != "Review some code" {
		t.Errorf("prompt = %+v", prompt)
	}
	run := toolByName(t, f, "run")
	if run.Kind != "" || run.Description != "Run a command" || !reflect.DeepEqual(run.Params, []string{"args"}) {
		t.Errorf("addTool = %+v", run)
	}
	bodyContains(t, f, run, "args.cmd")
}

func TestGoPromptsAndResources(t *testing.T) {
	f := load(t, "primitives.go")
	prompt := toolByName(t, f, "review")
	if prompt.Kind != "prompt" || prompt.Description != "Review code" {
		t.Errorf("prompt = %+v", prompt)
	}
	res := toolByName(t, f, "notes")
	if res.Kind != "resource" || !res.HasBody() {
		t.Errorf("resource = %+v", res)
	}
}

func TestTOMLClientConfig(t *testing.T) {
	f := load(t, "codex_config.toml")
	if !f.IsMCPConfig || len(f.Servers) != 3 {
		t.Fatalf("servers = %+v", f.Servers)
	}
	by := map[string]source.ConfigServer{}
	for _, s := range f.Servers {
		by[s.Name] = s
	}
	gh := by["github"]
	if gh.Command != "npx" || !reflect.DeepEqual(gh.Args, []string{"-y", "@modelcontextprotocol/server-github"}) || gh.Env["GITHUB_TOKEN"] == "" || gh.Line != 4 {
		t.Errorf("github = %+v", gh)
	}
	if by["docs"].URL != "http://docs.vendor.dev/mcp" {
		t.Errorf("docs = %+v", by["docs"])
	}
	db := by["db"]
	if !reflect.DeepEqual(db.Args, []string{"run", "-i", "--rm", "acme/db-mcp:2.0.1"}) || db.Env["DB_DSN"] != "${DB_DSN}" {
		t.Errorf("multi-line array / dotted env table: %+v", db)
	}
}

func TestYAMLClientConfig(t *testing.T) {
	f := load(t, "continue.yaml")
	if !f.IsMCPConfig || len(f.Servers) != 2 {
		t.Fatalf("list form: %+v", f.Servers)
	}
	if s := f.Servers[1]; s.Name != "search" || !reflect.DeepEqual(s.Args, []string{"-y", "some-search-mcp"}) || s.Line != 4 {
		t.Errorf("search = %+v", s)
	}
	g := load(t, "servers.yaml")
	if len(g.Servers) != 1 || g.Servers[0].Name != "files" || g.Servers[0].Command != "uvx" || g.Servers[0].Line != 2 {
		t.Errorf("map form: %+v", g.Servers)
	}
	for _, content := range []string{"key: [unclosed", "just: text\nnothing: here\n", "mcpServers: 5\n"} {
		f := source.NewFile("x.yaml", source.YAML, content)
		Extract(f)
		if f.IsMCPConfig || len(f.Servers) != 0 {
			t.Errorf("%q should not be a client config", content)
		}
	}
}

func TestParseTOMLEdgeCases(t *testing.T) {
	doc := parseTOML("a.b = 1\n[t]\nk = 'lit # not a comment'  # comment\nlist = [ \"x\",\n  \"y\" ]\ninline = { p = \"1\", q = [\"2\"] }\n\"quoted.key\" = true\n[[array]]\nz = 1\n")
	tbl, _ := doc["t"].(map[string]any)
	if tbl["k"] != "lit # not a comment" {
		t.Errorf("k = %v", tbl["k"])
	}
	if l, _ := tbl["list"].([]any); len(l) != 2 || l[1] != "y" {
		t.Errorf("list = %v", tbl["list"])
	}
	if in, _ := tbl["inline"].(map[string]any); in["p"] != "1" {
		t.Errorf("inline = %v", tbl["inline"])
	}
	if ab, _ := doc["a"].(map[string]any); ab["b"] != "1" {
		t.Errorf("dotted key = %v", doc["a"])
	}
	if parseTOML("= = =\n[unclosed\n") == nil {
		t.Error("garbage must not return nil")
	}
}

func TestDynamicDescriptionsAreMarked(t *testing.T) {
	py := source.NewFile("s.py", source.Python, "DESC = 'x'\n\n@mcp.tool(description=DESC)\ndef a(p: str):\n    return p\n\n@mcp.tool()\ndef b(p: str):\n    return p\n\n@mcp.tool(description=\"literal\")\ndef c(p: str):\n    return p\n")
	Extract(py)
	got := map[string][2]bool{}
	for _, tl := range py.Tools {
		got[tl.Name] = [2]bool{tl.DescriptionDynamic, tl.Description != ""}
	}
	if got["a"] != [2]bool{true, false} || got["b"] != [2]bool{false, false} || got["c"] != [2]bool{false, true} {
		t.Errorf("python: %v", got)
	}
	ts := source.NewFile("s.ts", source.TypeScript, "server.tool(\"x\", DESCRIPTION, { a: z.string() }, async ({ a }) => { return a; });\nserver.tool(\"y\", \"literal\", { a: z.string() }, async ({ a }) => { return a; });\nserver.tool(\"z\", { a: z.string() }, async ({ a }) => { return a; });\nserver.tool(\"w\", `built ${x}`, { a: z.string() }, async ({ a }) => { return a; });\n")
	Extract(ts)
	byName := map[string]bool{}
	for _, tl := range ts.Tools {
		byName[tl.Name] = tl.DescriptionDynamic
	}
	if !byName["x"] || byName["y"] || byName["z"] || byName["w"] { // a template literal is parsed as text
		t.Errorf("typescript: %v", byName)
	}
	g := source.NewFile("s.go", source.Go, "package main\nfunc f() {\n\ts.AddTool(mcp.NewTool(\"t\", mcp.WithDescription(desc)), h)\n\ts.AddTool(mcp.NewTool(\"u\", mcp.WithDescription(\"ok\")), h)\n\ts.AddTool(mcp.NewTool(\"v\"), h)\n}\nfunc h() {}\n")
	Extract(g)
	gm := map[string]bool{}
	for _, tl := range g.Tools {
		gm[tl.Name] = tl.DescriptionDynamic
	}
	if !gm["t"] || gm["u"] || gm["v"] {
		t.Errorf("go: %v", gm)
	}
}

func TestGoDeclarationsOfAddToolAreNotRegistrations(t *testing.T) {
	src := "package mcp\n\ntype Server struct{}\n\nfunc (s *Server) AddTool(t *Tool, h ToolHandler) {\n\ts.tools = append(s.tools, t)\n}\n\ntype API interface {\n\tAddTool(t *Tool, h ToolHandler)\n}\n\nfunc use(s *Server) {\n\tAddTool(s, &mcp.Tool{Name: \"real\"}, handler)\n}\n\nfunc handler() {}\n"
	f := source.NewFile("server.go", source.Go, src)
	Extract(f)
	var names []string
	for _, tl := range f.Tools {
		names = append(names, tl.Name)
	}
	if len(names) != 1 || names[0] != "real" {
		t.Errorf("tools = %v, want only the real registration", names)
	}
}

func TestFixedParamsAndQuotedAnnotationKeys(t *testing.T) {
	py := source.NewFile("s.py", source.Python, "@mcp.tool(annotations={\"title\": \"Delete\", \"destructiveHint\": True})\ndef delete_it(name: str, limit: int, kind: Literal[\"a\", \"b\"], flag: bool = False, maybe: Optional[int] = None, many: list[int] = []):\n    return name\n")
	Extract(py)
	if len(py.Tools) != 1 {
		t.Fatalf("tools = %+v", py.Tools)
	}
	tl := py.Tools[0]
	if tl.Hint("destructiveHint") != "true" {
		t.Errorf("dict-style annotation not parsed: %v", tl.Annotations)
	}
	want := []string{"limit", "kind", "flag", "maybe"}
	if !reflect.DeepEqual(tl.FixedParams, want) {
		t.Errorf("FixedParams = %v, want %v (str and list[int] stay tainted)", tl.FixedParams, want)
	}
	ts := source.NewFile("s.ts", source.TypeScript, "server.tool(\"x\", \"d\", { path: z.string(), n: z.number().int(), mode: z.enum([\"a\"]), on: z.boolean().optional() }, async ({ path, n, mode, on }) => { return path; });\n")
	Extract(ts)
	if len(ts.Tools) != 1 || !reflect.DeepEqual(ts.Tools[0].FixedParams, []string{"n", "mode", "on"}) {
		t.Errorf("zod fixed params: %+v", ts.Tools)
	}
}
