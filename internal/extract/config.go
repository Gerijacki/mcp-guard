package extract

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/Gerijacki/mcp-guard/internal/source"
)

var jsonLineCommentRe = regexp.MustCompile(`(?m)^\s*//.*$`)
var jsonTrailingCommaRe = regexp.MustCompile(`,(\s*[}\]])`)

// extractConfig recognizes MCP client configuration files (Claude Desktop, Claude Code,
// Cursor, VS Code, Windsurf, Cline, Zed, ...) by content: a JSON object with an
// "mcpServers"-style map of server entries.
func extractConfig(f *source.File) {
	var doc map[string]any
	data := f.Content
	if err := json.Unmarshal([]byte(data), &doc); err != nil {
		// Tolerate JSONC (VS Code / Cursor style): line comments and trailing commas.
		data = jsonTrailingCommaRe.ReplaceAllString(jsonLineCommentRe.ReplaceAllString(data, ""), "$1")
		if err := json.Unmarshal([]byte(data), &doc); err != nil {
			return
		}
	}
	servers := findServers(doc)
	if servers == nil {
		return
	}
	f.IsMCPConfig = true
	names := make([]string, 0, len(servers))
	for name := range servers {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		entry, ok := servers[name].(map[string]any)
		if !ok {
			continue
		}
		cs := source.ConfigServer{
			Name:    name,
			Line:    f.FindLine(`"`+name+`"`, 1),
			Command: str(entry["command"]),
			URL:     firstNonEmpty(str(entry["url"]), str(entry["serverUrl"])),
			Env:     strMap(entry["env"]),
			Headers: strMap(entry["headers"]),
		}
		if args, ok := entry["args"].([]any); ok {
			for _, a := range args {
				cs.Args = append(cs.Args, str(a))
			}
		}
		f.Servers = append(f.Servers, cs)
	}
}

// findServers returns the server map of an MCP client config, or nil.
func findServers(doc map[string]any) map[string]any {
	for _, key := range []string{"mcpServers", "mcp_servers", "servers", "context_servers"} {
		if m, ok := doc[key].(map[string]any); ok && looksLikeServers(m) {
			return m
		}
	}
	if mcp, ok := doc["mcp"].(map[string]any); ok { // VS Code settings.json: "mcp": {"servers": {...}}
		return findServers(mcp)
	}
	return nil
}

func looksLikeServers(m map[string]any) bool {
	for _, v := range m {
		entry, ok := v.(map[string]any)
		if !ok {
			return false
		}
		_, hasCmd := entry["command"]
		_, hasURL := entry["url"]
		_, hasType := entry["type"]
		if hasCmd || hasURL || hasType {
			return true
		}
	}
	return false
}

func str(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	default:
		return fmt.Sprint(x)
	}
}

func strMap(v any) map[string]string {
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, val := range m {
		out[k] = str(val)
	}
	return out
}

func firstNonEmpty(xs ...string) string {
	for _, x := range xs {
		if strings.TrimSpace(x) != "" {
			return x
		}
	}
	return ""
}
