package rules

import (
	"fmt"
	"path"
	"regexp"
	"strings"

	"github.com/Gerijacki/mcp-guard/internal/finding"
	"github.com/Gerijacki/mcp-guard/internal/source"
)

// MCPG012: a tool parameter becomes an argument of a well-known CLI without "--", so a
// value starting with "-" is parsed as an option (argument injection).
type argInjectionRule struct{ ext extension }

// Programs whose options can write files, run commands, load config or exfiltrate data.
var optionDangerousPrograms = map[string]bool{
	"git": true, "curl": true, "wget": true, "tar": true, "find": true, "rsync": true, "ssh": true, "scp": true,
	"sftp": true, "npm": true, "npx": true, "pnpm": true, "yarn": true, "pip": true, "pip3": true, "docker": true,
	"kubectl": true, "sed": true, "awk": true, "zip": true, "unzip": true, "7z": true, "make": true,
	"psql": true, "mysql": true, "sqlite3": true, "ffmpeg": true, "convert": true, "gcc": true, "xargs": true,
}

var (
	argSinks = map[source.Language]*regexp.Regexp{
		source.Python:     regexp.MustCompile(`\bsubprocess\.(?:run|call|Popen|check_output|check_call)\s*\(|\basyncio\.create_subprocess_exec\s*\(`),
		source.TypeScript: regexp.MustCompile(`\b(?:spawn|spawnSync|execFile|execFileSync|execa|execaSync)\s*\(`),
		source.Go:         regexp.MustCompile(`\bexec\.Command(?:Context)?\s*\(`),
	}
	// Evidence that a leading "-" is rejected or the value is validated by pattern.
	dashGuardRe = regexp.MustCompile(`(?i)\.startswith\s*\(\s*["']-|\.startsWith\s*\(\s*["']-|strings\.HasPrefix\s*\([^,]+,\s*"-"|\.lstrip\s*\(\s*["']-|\bre\.(?:fullmatch|match)\s*\(|\.MatchString\s*\(|\.test\s*\(|isalnum\s*\(|isalpha\s*\(|isidentifier\s*\(|isdigit\s*\(|\bregexp\.(?:MustCompile|Compile)\b`)
	shellTrueRe = regexp.MustCompile(`\bshell\s*(?:=|:)\s*(?:True|true)\b`)
)

func (argInjectionRule) Meta() Meta {
	return Meta{
		ID:       "MCPG012",
		Name:     "argument-injection",
		Severity: finding.High,
		Summary:  "Tool parameter passed to a CLI without `--`, so it can be parsed as an option",
		Description: "A model-controlled value is placed in the argument list of a program such as git, curl, tar, " +
			"find or ssh. Avoiding the shell does not help: a value like `--output=/etc/cron.d/x`, `-c core.sshCommand=...` " +
			"or `--upload-pack=...` is parsed as an option and can write files, run commands or leak data. " +
			"This is the bug class behind several MCP server CVEs (git, filesystem and fetch tools).",
		Remediation: "Put `--` before user-supplied positional arguments (`[\"git\", \"log\", \"--\", branch]`), reject " +
			"values that start with `-`, validate values against a pattern or allowlist, and prefer a library " +
			"API over spawning the CLI.",
		CWE:   []string{"CWE-88"},
		OWASP: []string{"MCP05:2025", "LLM05:2025", "ASI02:2026"},
	}
}

func (r argInjectionRule) Check(f *source.File) []finding.Finding {
	return r.CheckTools(f, taintBodies(f))
}

// CheckTools runs the rule on the given tools (the file's tools plus helper views).
func (r argInjectionRule) CheckTools(f *source.File, tools []source.Tool) []finding.Finding {
	sink := argSinks[f.Language]
	if sink == nil {
		return nil
	}
	guardRe := r.ext.withSanitizers(dashGuardRe)
	if !containsAny(f.Content, "subprocess", "spawn", "execFile", "execa", "exec.Command", "create_subprocess_exec") {
		return nil
	}
	var out []finding.Finding
	for _, t := range tools {
		if guardRe.MatchString(f.CodeText(t)) {
			continue
		}
		lists := map[string]string{} // list variables: cmd = ["git", "log", branch]
		validated := map[string]bool{}
		walkTaint(f, t, shellQuoteRe, func(st source.Stmt, taint *taintSet) {
			if a, ok := parseAssign(st.Text); ok && len(a.ids) == 1 && strings.HasPrefix(strings.TrimSpace(a.rhs), "[") {
				lists[a.ids[0]] = strings.TrimSpace(a.rhs)
			}
			if commandMembershipRe.MatchString(st.Text) {
				for _, id := range taint.order {
					if taint.has[id] && source.ContainsIdent(st.Text, id) {
						validated[id] = true
					}
				}
			}
			loc := sink.FindStringIndex(st.Text)
			if loc == nil || shellTrueRe.MatchString(st.Text) {
				return
			}
			elems := argvElements(st.Text, loc, f.Language, lists)
			if len(elems) < 2 {
				return
			}
			prog := strings.ToLower(path.Base(strings.Trim(strings.TrimSpace(elems[0]), "\"'`")))
			if !optionDangerousPrograms[prog] {
				return
			}
			for i := 1; i < len(elems); i++ {
				e := strings.TrimSpace(elems[i])
				if e == `"--"` || e == `'--'` {
					return // everything after "--" is positional
				}
				if p := taint.find(e); p != "" && !validated[p] && !strings.HasPrefix(e, "...") {
					out = append(out, newFinding(r.Meta(), f, st.Line, finding.High, t.Name, fmt.Sprintf(
						"%s %q passes model-controlled %q as an argument of %s without \"--\", so a value starting with \"-\" is parsed as an option (argument injection).",
						t.Noun(), t.Name, p, prog)))
					return
				}
			}
		})
	}
	return out
}

// argvElements returns the program followed by its arguments for the process call at loc.
func argvElements(stmt string, loc []int, lang source.Language, lists map[string]string) []string {
	args := callArgs(stmt, loc[1]-1, lang)
	if len(args) == 0 {
		return nil
	}
	switch lang {
	case source.Go:
		if strings.Contains(stmt[loc[0]:loc[1]], "Context") && len(args) > 0 {
			args = args[1:]
		}
		return args
	case source.TypeScript:
		elems := []string{args[0]}
		if len(args) > 1 {
			elems = append(elems, listElements(args[1], lang, lists)...)
		}
		return elems
	default:
		return listElements(args[0], lang, lists)
	}
}

// listElements splits a list literal ("[a, b]") or resolves a variable holding one.
func listElements(s string, lang source.Language, lists map[string]string) []string {
	s = strings.TrimSpace(s)
	if l, ok := lists[s]; ok {
		s = l
	}
	if !strings.HasPrefix(s, "[") {
		return nil
	}
	close := source.MatchClose(s, 0, lang)
	if close < 0 {
		return nil
	}
	var out []string
	for _, seg := range source.SplitArgs(s, 1, close, lang) {
		out = append(out, seg.Text(s))
	}
	return out
}
