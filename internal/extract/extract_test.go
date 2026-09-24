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
