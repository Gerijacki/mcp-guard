package rules

import (
	"fmt"
	"regexp"
	"strings"
	"unicode"

	"github.com/Gerijacki/mcp-guard/internal/finding"
	"github.com/Gerijacki/mcp-guard/internal/source"
)

// MCPG006: a destructive tool has no confirmation, allowlist or limit.
type destructiveRule struct{}

var destructiveVerbs = map[string]bool{
	"delete": true, "del": true, "remove": true, "rm": true, "drop": true, "destroy": true,
	"kill": true, "terminate": true, "truncate": true, "purge": true, "wipe": true, "erase": true,
	"exec": true, "execute": true, "shell": true, "uninstall": true, "revoke": true,
	"shutdown": true, "reboot": true, "overwrite": true, "unlink": true, "transfer": true, "deploy": true,
	"prune": true, "flush": true, "refund": true, "rollback": true,
}

// destructiveOps finds irreversible operations in a handler whose name does not say so
// (a tool called "cleanup" that runs rmtree, "sync" that issues DELETE FROM).
var destructiveOps = compileByLang(map[source.Language]string{
	source.Python:     `\bshutil\.rmtree\s*\(|\bos\.(?:remove|unlink|rmdir|removedirs)\s*\(|\.unlink\s*\(|\b(?:DROP\s+(?:TABLE|DATABASE)|DELETE\s+FROM|TRUNCATE\s+TABLE)\b|\b(?:requests|httpx)\.delete\s*\(`,
	source.TypeScript: `\b(?:rmSync|unlinkSync|rmdirSync)\s*\(|\bfs(?:\.promises)?\.(?:rm|unlink|rmdir)\s*\(|\b(?:DROP\s+(?:TABLE|DATABASE)|DELETE\s+FROM|TRUNCATE\s+TABLE)\b|\baxios\.delete\s*\(|method\s*:\s*['"]DELETE['"]`,
	source.Go:         `\bos\.(?:Remove|RemoveAll)\s*\(|\b(?:DROP\s+(?:TABLE|DATABASE)|DELETE\s+FROM|TRUNCATE\s+TABLE)\b|\bhttp\.MethodDelete\b`,
})

var scopeMarkerRe = regexp.MustCompile(`(?i)confirm|dry[_-]?run|allow[_-]?list|allowed|validat|sandbox|restrict|whitelist|block[_-]?list|deny[_-]?list|\bmax_\w+|\bmax(?:Count|Items|Results|Files|Rows|Deletes|Batch)\b|\blimit|rate[_-]?limit|throttle|approv|elicit|protected|forbidden|read[_-]?only|safe[_-]?(?:guard|mode)|require[_-]?(?:confirmation|approval)|quota|budget|cooldown|\bMAX_|ALLOWED_|PROTECTED_`)

func (destructiveRule) Meta() Meta {
	return Meta{
		ID:       "MCPG006",
		Name:     "unscoped-destructive-tool",
		Severity: finding.Medium,
		Summary:  "Destructive tool without confirmation, allowlist or limits",
		Description: "The tool is destructive (it declares destructiveHint: true, or its name says it deletes, " +
			"drops, kills, executes, transfers or deploys) but its handler contains no guard: no confirmation " +
			"step, no allowlist of targets, no dry-run, no rate or size limit. A single hallucinated or " +
			"injected call can cause irreversible damage, and a loop can repeat it many times.",
		Remediation: "Scope the tool: restrict targets to an allowlist or a sandbox directory, require an " +
			"explicit confirmation (MCP elicitation, a confirm parameter, or a dry_run default), cap how many " +
			"items one call may affect, and rate-limit it. Declare destructiveHint: true so clients can ask " +
			"the user before running it.",
		CWE:   []string{"CWE-749", "CWE-770"},
		OWASP: []string{"MCP02:2025", "LLM06:2025", "ASI02:2026"},
	}
}

func (r destructiveRule) Check(f *source.File) []finding.Finding {
	var out []finding.Finding
	for _, t := range toolBodies(f) {
		// Resources and prompts only read; a name like "deploy-status" is not an action.
		if t.Dispatcher || t.Kind != "" || t.Hint("readOnlyHint") == "true" {
			continue
		}
		annotated := t.Hint("destructiveHint") == "true"
		verb := destructiveWord(t.Name)
		if !annotated && t.Hint("destructiveHint") == "false" {
			continue
		}
		code := f.CodeText(t)
		op := ""
		if verb == "" && !annotated {
			if re := destructiveOps[f.Language]; re != nil {
				op = strings.TrimSpace(re.FindString(code))
			}
			if op == "" {
				continue
			}
		}
		if scopeMarkerRe.MatchString(code) {
			continue
		}
		var msg string
		switch {
		case op != "":
			msg = fmt.Sprintf("%s %q performs a destructive operation (%s) but its handler has no confirmation, allowlist or limit, and it does not declare destructiveHint: true.", t.Noun(), t.Name, op)
		case annotated:
			msg = fmt.Sprintf("%s %q is marked destructive (destructiveHint: true) but its handler has no confirmation, allowlist or limit.", t.Noun(), t.Name)
		default:
			msg = fmt.Sprintf("%s %q looks destructive (%q) but its handler has no confirmation, allowlist or limit, and it does not declare destructiveHint: true.", t.Noun(), t.Name, verb)
		}
		out = append(out, newFinding(r.Meta(), f, t.Line, finding.Medium, t.Name, msg))
	}
	return out
}

// destructiveWord returns the first destructive verb in a tool name split on
// snake_case, kebab-case, dots and camelCase boundaries.
func destructiveWord(name string) string {
	for _, w := range splitWords(name) {
		if destructiveVerbs[w] {
			return w
		}
	}
	return ""
}

func splitWords(name string) []string {
	var words []string
	var cur strings.Builder
	runes := []rune(name)
	flush := func() {
		if cur.Len() > 0 {
			words = append(words, strings.ToLower(cur.String()))
			cur.Reset()
		}
	}
	for i, c := range runes {
		switch {
		case !unicode.IsLetter(c) && !unicode.IsDigit(c):
			flush()
		case unicode.IsUpper(c) && i > 0 && (unicode.IsLower(runes[i-1]) || (i+1 < len(runes) && unicode.IsLower(runes[i+1]) && unicode.IsUpper(runes[i-1]))):
			flush()
			cur.WriteRune(c)
		default:
			cur.WriteRune(c)
		}
	}
	flush()
	return words
}
