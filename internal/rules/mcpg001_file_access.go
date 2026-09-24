package rules

import (
	"fmt"
	"regexp"

	"github.com/Gerijacki/mcp-guard/internal/finding"
	"github.com/Gerijacki/mcp-guard/internal/source"
)

// MCPG001: a tool parameter reaches a filesystem operation without a containment check.
type fileAccessRule struct{}

var (
	fileWriteSinks = compileByLang(map[source.Language]string{
		source.Python:     `\.write_(?:text|bytes)\s*\(|\bos\.(?:remove|unlink|rmdir|removedirs|rename|renames|replace|makedirs|mkdir|chmod|chown|truncate|symlink|link)\s*\(|\bshutil\.(?:rmtree|move|copy|copy2|copyfile|copytree|chown)\s*\(|\.(?:unlink|rmdir|touch|mkdir|symlink_to|hardlink_to)\s*\(`,
		source.TypeScript: `\b(?:writeFile|writeFileSync|appendFile|appendFileSync|unlink|unlinkSync|rmSync|rmdir|rmdirSync|renameSync|createWriteStream|copyFile|copyFileSync|cp|cpSync|mkdirSync|truncate|truncateSync|chmod|chmodSync|symlink|symlinkSync|outputFile|outputFileSync|emptyDir|removeSync)\s*\(|\.(?:rm|rename|mkdir)\s*\(`,
		source.Go:         `\b(?:os|ioutil)\.(?:WriteFile|Create|OpenFile|Remove|RemoveAll|Rename|Mkdir|MkdirAll|Chmod|Chown|Truncate|Symlink|Link)\s*\(`,
	})
	fileReadSinks = compileByLang(map[source.Language]string{
		source.Python:     `(?:^|[^.\w])open\s*\(|\bio\.open\s*\(|\baiofiles\.open\s*\(|\.read_(?:text|bytes)\s*\(|\bos\.(?:listdir|scandir|walk)\s*\(|\bglob\.i?glob\s*\(|\bsend_file\s*\(|\bFileResponse\s*\(`,
		source.TypeScript: `\b(?:readFile|readFileSync|createReadStream|readdir|readdirSync|opendir|opendirSync|readJson|readJsonSync)\s*\(|\bBun\.file\s*\(`,
		source.Go:         `\b(?:os|ioutil)\.(?:ReadFile|Open|ReadDir)\s*\(|\bfilepath\.(?:Walk|WalkDir|Glob)\s*\(|\bhttp\.ServeFile\s*\(`,
	})
	// open(p, "w") / open(p, mode="a") turn a Python read sink into a write sink.
	pyWriteModeRe = regexp.MustCompile(`["'](?:[wax]|r\+)[bt+]*["']|mode\s*=\s*["'][wax+]`)

	// Evidence that the handler confines paths to an allowed root.
	pathGuardRe = regexp.MustCompile(`(?i)is_relative_to|commonpath|\.startswith\s*\(|\.startsWith\s*\(|path\.relative\s*\(|filepath\.IsLocal|filepath\.Rel\s*\(|strings\.HasPrefix\s*\(|OpenRoot|OpenInRoot|securejoin|safe_join|secure_filename|sanitize_?(?:file)?_?path|is_?within|is_?inside|is_?sub_?path|ensure_?within|assert_?(?:within|inside)|validate_?path|resolve_?safe|safe_?path|allowed_?(?:dirs?|directories|roots?|paths?)|ALLOWED_(?:DIRS?|DIRECTORIES|ROOTS?|PATHS?)`)
)

func (fileAccessRule) Meta() Meta {
	return Meta{
		ID:       "MCPG001",
		Name:     "unrestricted-file-access",
		Severity: finding.High,
		Summary:  "Tool parameter reaches a filesystem operation without a path containment check",
		Description: "A tool passes a model-controlled path straight to a filesystem API. Because the LLM " +
			"(or a prompt injection it has read) chooses the value, it can use absolute paths or `../` " +
			"sequences to read, overwrite or delete any file the server process can access " +
			"(SSH keys, cloud credentials, other MCP configs, source code).",
		Remediation: "Resolve the path (realpath/resolve, following symlinks) and verify it stays inside an " +
			"explicit allowed root before using it (Python: Path.resolve().is_relative_to(ROOT); " +
			"Node: path.relative(ROOT, p) must not start with '..'; Go: os.OpenRoot / filepath.IsLocal). " +
			"Prefer read-only access unless writes are required.",
		CWE:   []string{"CWE-22", "CWE-73"},
		OWASP: []string{"MCP02:2025", "LLM06:2025", "ASI02:2026"},
	}
}

func (r fileAccessRule) Check(f *source.File) []finding.Finding {
	writes, reads := fileWriteSinks[f.Language], fileReadSinks[f.Language]
	if writes == nil {
		return nil
	}
	var out []finding.Finding
	for _, t := range toolBodies(f) {
		if pathGuardRe.MatchString(f.BodyText(t)) {
			continue
		}
		walkTaint(f, t, pathGuardRe, func(st source.Stmt, taint *taintSet) {
			isWrite := writes.MatchString(st.Text)
			isRead := !isWrite && reads.MatchString(st.Text)
			if isRead && f.Language == source.Python && pyWriteModeRe.MatchString(st.Text) {
				isWrite, isRead = true, false
			}
			if !isWrite && !isRead {
				return
			}
			p := taint.find(st.Text)
			if p == "" {
				return
			}
			sev, op := finding.High, "write/delete"
			if isRead {
				sev, op = finding.Medium, "read"
			}
			out = append(out, newFinding(r.Meta(), f, st.Line, sev, t.Name, fmt.Sprintf(
				"Tool %q passes model-controlled %q to a file %s operation without checking it stays inside an allowed directory (path traversal).",
				t.Name, p, op)))
		})
	}
	return out
}
