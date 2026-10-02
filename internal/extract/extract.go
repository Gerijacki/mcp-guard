// Package extract discovers MCP tool definitions (name, description, parameters,
// annotations and handler body) in source files, and MCP servers in client configs.
//
// Extraction is heuristic: it recognizes the registration patterns of the official
// SDKs and popular frameworks (FastMCP, @modelcontextprotocol/sdk, mark3labs/mcp-go,
// modelcontextprotocol/go-sdk) without building a full AST.
package extract

import (
	"regexp"
	"strings"
	"sync"

	"github.com/Gerijacki/mcp-guard/internal/source"
)

// Extract populates f.Tools, f.Servers and f.IsMCPConfig.
func Extract(f *source.File) {
	switch f.Language {
	case source.Python:
		f.Tools = extractPython(f)
	case source.TypeScript:
		f.Tools = extractTypeScript(f)
	case source.Go:
		f.Tools = extractGo(f)
	case source.JSON, source.YAML, source.TOML:
		extractConfig(f)
	}
	if f.Language.IsCode() {
		extractFuncs(f)
	}
}

// hintRe matches MCP tool annotation hints in all supported syntaxes:
//
//	destructiveHint=True            (Python)
//	destructiveHint: true           (TypeScript)
//	mcp.WithDestructiveHintAnnotation(true), DestructiveHint: mcp.ToBoolPtr(true)  (Go)
var hintRe = regexp.MustCompile(`(?i)\b(?:With)?(destructive|readOnly|idempotent|openWorld)Hint(?:Annotation)?["']?\s*[:=(]\s*(?:[\w.]+\(\s*)?&?\s*(true|false)\b`)

func parseHints(text string) map[string]string {
	out := map[string]string{}
	for _, m := range hintRe.FindAllStringSubmatch(text, -1) {
		out[strings.ToLower(m[1])+"hint"] = strings.ToLower(m[2])
	}
	return out
}

// keyString finds `key = "literal"` or `key: "literal"` inside text and returns the
// decoded literal and its offset within text.
func keyString(text, key string, lang source.Language) (string, int, bool) {
	for _, m := range keyRe(key).FindAllStringIndex(text, -1) {
		if v, _, ok := source.ParseStringLiteral(text, m[1], lang); ok {
			return v, source.SkipSpace(text, m[1]), true
		}
	}
	return "", 0, false
}

var regexCache sync.Map // pattern -> *regexp.Regexp

// cachedRegexp compiles pattern once. Extractors build patterns around names found in the
// scanned code; doing that per tool or per identifier is measurable on large trees.
func cachedRegexp(pattern string) *regexp.Regexp {
	if re, ok := regexCache.Load(pattern); ok {
		return re.(*regexp.Regexp)
	}
	re := regexp.MustCompile(pattern)
	regexCache.Store(pattern, re)
	return re
}

// hasKey reports whether text assigns or declares key at all, whatever its value.
func hasKey(text, key string) bool { return keyRe(key).MatchString(text) }

func keyRe(key string) *regexp.Regexp {
	return cachedRegexp(`\b` + regexp.QuoteMeta(key) + `["']?\s*[:=]\s*`)
}

// allStrings returns every string literal that follows a match of re in text.
func allStrings(text string, re *regexp.Regexp, lang source.Language) []string {
	var out []string
	for _, m := range re.FindAllStringIndex(text, -1) {
		if v, _, ok := source.ParseStringLiteral(text, m[1], lang); ok && strings.TrimSpace(v) != "" {
			out = append(out, v)
		}
	}
	return out
}

var schemaDescRe = regexp.MustCompile(`["']?description["']?\s*:\s*`)

// schemaDescriptions returns the "description" strings nested in a raw JSON-Schema literal
// (the inputSchema of a tool definition). They reach the model like any other description.
func schemaDescriptions(text string, lang source.Language) []string {
	i := strings.Index(text, "inputSchema")
	if i < 0 {
		i = strings.Index(text, "input_schema")
	}
	if i < 0 {
		return nil
	}
	return allStrings(text[i:], schemaDescRe, lang)
}

func hasTool(tools []source.Tool, name string) bool {
	for _, t := range tools {
		if t.Name == name {
			return true
		}
	}
	return false
}
