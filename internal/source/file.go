// Package source holds the in-memory model of a scanned file (content, language,
// extracted MCP tools and config servers) plus the lightweight lexing helpers
// that extractors and rules share.
package source

import (
	"path/filepath"
	"sort"
	"strings"
)

// Language is the language family of a file. JavaScript is folded into TypeScript
// because the MCP SDK patterns are identical.
type Language string

const (
	Unknown    Language = ""
	Python     Language = "python"
	TypeScript Language = "typescript"
	Go         Language = "go"
	JSON       Language = "json"
	YAML       Language = "yaml"
	TOML       Language = "toml"
	Env        Language = "env"
)

// IsCode reports whether the language is a programming language we extract tools from.
func (l Language) IsCode() bool {
	return l == Python || l == TypeScript || l == Go
}

// DetectLanguage maps a path to a Language, or Unknown if the file should be skipped.
func DetectLanguage(path string) Language {
	base := strings.ToLower(filepath.Base(path))
	if base == ".env" || strings.HasPrefix(base, ".env.") || strings.HasSuffix(base, ".env") {
		return Env
	}
	switch filepath.Ext(base) {
	case ".py":
		return Python
	case ".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs":
		if strings.HasSuffix(base, ".min.js") || strings.HasSuffix(base, ".d.ts") {
			return Unknown
		}
		return TypeScript
	case ".go":
		return Go
	case ".json", ".jsonc":
		return JSON
	case ".yaml", ".yml":
		return YAML
	case ".toml":
		return TOML
	}
	return Unknown
}

// ParseLanguage parses a user-supplied language name (used by custom rules).
func ParseLanguage(v string) (Language, bool) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "python", "py":
		return Python, true
	case "typescript", "ts", "javascript", "js":
		return TypeScript, true
	case "go", "golang":
		return Go, true
	case "json":
		return JSON, true
	case "yaml", "yml":
		return YAML, true
	case "toml":
		return TOML, true
	case "env", "dotenv":
		return Env, true
	}
	return Unknown, false
}

// Tool is an MCP tool discovered in source code.
type Tool struct {
	Name        string
	Description string
	// ParamDescriptions holds per-parameter description strings (also shown to the model).
	ParamDescriptions []string
	// Params are the identifiers in the handler that carry model-controlled input.
	Params []string
	// Annotations maps lower-cased MCP hint names (e.g. "destructivehint") to "true"/"false".
	Annotations map[string]string
	// Line is where the tool is declared.
	Line int
	// DescriptionLine is where the description string starts (0 if unknown).
	DescriptionLine int
	// BodyFrom/BodyTo are the byte offsets [from, to) of the handler body and
	// BodyStart/BodyEnd its 1-based inclusive lines. All are 0 when only the tool
	// metadata was found (e.g. list_tools definitions).
	BodyFrom, BodyTo   int
	BodyStart, BodyEnd int
	// Dispatcher is true for low-level call_tool handlers that serve many tools.
	Dispatcher bool
}

// HasBody reports whether the handler body is known.
func (t Tool) HasBody() bool { return t.BodyTo > t.BodyFrom }

// Hint returns the value of an MCP annotation hint ("true"/"false"), or "" if unset.
func (t Tool) Hint(name string) string { return t.Annotations[strings.ToLower(name)] }

// ConfigServer is one entry of an MCP client configuration (mcp.json and friends).
type ConfigServer struct {
	Name    string
	Line    int
	Command string
	Args    []string
	URL     string
	Env     map[string]string
	Headers map[string]string
}

// File is a scanned file.
type File struct {
	// Path is the slash-separated path used in reports.
	Path     string
	Language Language
	Content  string
	Lines    []string

	Tools       []Tool
	Servers     []ConfigServer
	IsMCPConfig bool

	lineStarts []int
	code       string
	codeDone   bool
}

// NewFile builds a File, normalizing CRLF line endings.
func NewFile(path string, lang Language, content string) *File {
	content = strings.ReplaceAll(content, "\r\n", "\n")
	f := &File{Path: path, Language: lang, Content: content}
	f.Lines = strings.Split(content, "\n")
	f.lineStarts = make([]int, 0, len(f.Lines))
	off := 0
	for _, l := range f.Lines {
		f.lineStarts = append(f.lineStarts, off)
		off += len(l) + 1
	}
	return f
}

// Code returns the content with comments blanked out (same offsets as Content). Extractors
// match against it so that commented-out registrations are not reported as tools.
func (f *File) Code() string {
	if !f.codeDone {
		f.code, f.codeDone = maskComments(f.Content, f.Language), true
	}
	return f.code
}

// LineAt returns the 1-based line number containing byte offset off.
func (f *File) LineAt(off int) int {
	i := sort.Search(len(f.lineStarts), func(i int) bool { return f.lineStarts[i] > off })
	if i == 0 {
		return 1
	}
	return i
}

// LineStart returns the byte offset of the start of 1-based line n.
func (f *File) LineStart(n int) int {
	if n < 1 {
		return 0
	}
	if n > len(f.lineStarts) {
		return len(f.Content)
	}
	return f.lineStarts[n-1]
}

// LineEnd returns the byte offset just past the end of 1-based line n (excluding the newline).
func (f *File) LineEnd(n int) int {
	if n < 1 {
		return 0
	}
	if n > len(f.Lines) {
		return len(f.Content)
	}
	return f.lineStarts[n-1] + len(f.Lines[n-1])
}

// Line returns 1-based line n, or "" when out of range.
func (f *File) Line(n int) string {
	if n < 1 || n > len(f.Lines) {
		return ""
	}
	return f.Lines[n-1]
}

// BodyText returns the raw text of the tool's handler body.
func (f *File) BodyText(t Tool) string {
	if !t.HasBody() {
		return ""
	}
	return f.Content[t.BodyFrom:t.BodyTo]
}

// SetBody records the handler body of t as the byte range [from, to) of f.
func (f *File) SetBody(t *Tool, from, to int) {
	from, to = max(0, from), min(len(f.Content), to)
	if to <= from {
		return
	}
	t.BodyFrom, t.BodyTo = from, to
	t.BodyStart, t.BodyEnd = f.LineAt(from), f.LineAt(to-1)
}

// ToolStatements returns the statements of the tool's handler body.
func (f *File) ToolStatements(t Tool) []Stmt {
	if !t.HasBody() {
		return nil
	}
	return f.StatementsIn(t.BodyFrom, t.BodyTo)
}

// FindLine returns the first 1-based line >= from that contains sub, or from if none does.
func (f *File) FindLine(sub string, from int) int {
	for n := max(from, 1); n <= len(f.Lines); n++ {
		if strings.Contains(f.Lines[n-1], sub) {
			return n
		}
	}
	return max(from, 1)
}
