package rules

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/Gerijacki/mcp-guard/internal/finding"
	"github.com/Gerijacki/mcp-guard/internal/source"
)

// MCPG010: model-controlled data is deserialized with a format that executes code, or
// chooses which module gets imported.
type deserializationRule struct{ ext extension }

type deserSink struct {
	re       *regexp.Regexp
	safe     *regexp.Regexp // statement-level evidence that makes the call safe (SafeLoader, weights_only=True)
	requires *regexp.Regexp // statement-level evidence the call is dangerous (allow_pickle=True)
	what     string
	severity finding.Severity
	// nonLiteral: the argument must not be a string literal (dynamic require/import).
	nonLiteral bool
}

var deserSinks = map[source.Language][]deserSink{
	source.Python: {
		{re: regexp.MustCompile(`\b(?:c?[Pp]ickle|dill|cloudpickle|marshal|jsonpickle|joblib|shelve)\.(?:loads?|decode|open)\s*\(|\bpd\.read_pickle\s*\(|\b_?pickle\.Unpickler\s*\(`), what: "pickle-style deserialization", severity: finding.Critical},
		{re: regexp.MustCompile(`\byaml\.(?:load|load_all|unsafe_load|full_load)\s*\(`), safe: regexp.MustCompile(`Loader\s*=\s*(?:yaml\.)?(?:C?SafeLoader|BaseLoader)|yaml\.safe_load`), what: "an unsafe YAML loader", severity: finding.Critical},
		{re: regexp.MustCompile(`\btorch\.load\s*\(`), safe: regexp.MustCompile(`weights_only\s*=\s*True`), what: "torch.load without weights_only=True", severity: finding.Critical},
		{re: regexp.MustCompile(`\b(?:np|numpy)\.load\s*\(`), requires: regexp.MustCompile(`allow_pickle\s*=\s*True`), what: "numpy.load with allow_pickle=True", severity: finding.Critical},
		{re: regexp.MustCompile(`\bimportlib\.import_module\s*\(|(?:^|[^.\w])__import__\s*\(`), what: "a dynamic module import", severity: finding.High},
	},
	source.TypeScript: {
		{re: regexp.MustCompile(`(?:^|[^.\w$])require\s*\(`), what: "require() with a dynamic path", severity: finding.High, nonLiteral: true},
		{re: regexp.MustCompile(`(?:^|[^.\w$])import\s*\(`), what: "import() with a dynamic path", severity: finding.High, nonLiteral: true},
		{re: regexp.MustCompile(`\b(?:serialize|nodeSerialize)\.unserialize\s*\(|\bunserialize\s*\(|\bv8\.deserialize\s*\(`), what: "node-serialize / v8 deserialization", severity: finding.Critical},
		{re: regexp.MustCompile(`\b(?:yaml|YAML|jsyaml)\.(?:load|loadAll)\s*\(`), safe: regexp.MustCompile(`(?:schema\s*:\s*(?:yaml\.)?(?:CORE|JSON|FAILSAFE)_SCHEMA|safeLoad)`), what: "an unsafe YAML schema", severity: finding.High},
	},
	source.Go: {
		{re: regexp.MustCompile(`\bplugin\.Open\s*\(`), what: "plugin.Open", severity: finding.Critical},
	},
}

var deserGuardRe = regexp.MustCompile(`(?i)allow(?:ed)?[_-]?(?:modules?|plugins?|classes|list|names?)|\bALLOWED_\w+|whitelist|RestrictedUnpickler|find_class|hmac\.(?:compare|new)|verify_?signature|\bnot\s+in\s+[A-Z]|\bin\s+[A-Z][A-Z0-9_]{2,}\b`)

func (deserializationRule) Meta() Meta {
	return Meta{
		ID:       "MCPG010",
		Name:     "unsafe-deserialization",
		Severity: finding.Critical,
		Summary:  "Tool parameter reaches pickle, an unsafe YAML loader or a dynamic import",
		Description: "A model-controlled value is passed to a deserializer that can build arbitrary objects " +
			"(pickle, marshal, yaml.load without SafeLoader, torch.load, numpy allow_pickle) or decides which " +
			"module is imported or loaded. Deserializing attacker-chosen bytes with these formats runs code " +
			"on the host, so a prompt injection that reaches the tool argument becomes remote code execution.",
		Remediation: "Use a data-only format (JSON) or the safe variant: yaml.safe_load, torch.load(weights_only=True), " +
			"numpy.load without allow_pickle. Never import or require a module named by tool input; map allowed " +
			"names to modules in a fixed dictionary instead.",
		CWE:   []string{"CWE-502", "CWE-94"},
		OWASP: []string{"MCP05:2025", "LLM05:2025", "ASI05:2026"},
	}
}

func (r deserializationRule) Check(f *source.File) []finding.Finding {
	return r.CheckTools(f, taintBodies(f))
}

// CheckTools runs the rule on the given tools (the file's tools plus helper views).
func (r deserializationRule) CheckTools(f *source.File, tools []source.Tool) []finding.Finding {
	sinks := deserSinks[f.Language]
	if sinks == nil {
		return nil
	}
	guardRe := r.ext.withSanitizers(deserGuardRe)
	if r.ext.sinks != nil {
		sinks = append(append([]deserSink(nil), sinks...), deserSink{re: r.ext.sinks, what: "a user-defined sink", severity: finding.High})
	}
	if r.ext.sinks == nil && !containsAny(f.Content, "pickle", "marshal", "dill", "joblib", "shelve", "yaml", "YAML", "torch", "numpy", "np.load", "import_module", "__import__", "require", "import(", "unserialize", "deserialize", "plugin.Open") {
		return nil
	}
	var out []finding.Finding
	for _, t := range tools {
		if guardRe.MatchString(f.CodeText(t)) {
			continue
		}
		walkTaint(f, t, nil, func(st source.Stmt, taint *taintSet) {
			for _, s := range sinks {
				loc := s.re.FindStringIndex(st.Text)
				if loc == nil {
					continue
				}
				if (s.safe != nil && s.safe.MatchString(st.Text)) || (s.requires != nil && !s.requires.MatchString(st.Text)) {
					continue
				}
				args := callArgs(st.Text, loc[1]-1, f.Language)
				if len(args) == 0 {
					continue
				}
				if s.nonLiteral && isStringLiteral(args[0]) {
					continue
				}
				p := taint.find(args[0])
				if p == "" {
					continue
				}
				out = append(out, newFinding(r.Meta(), f, st.Line, s.severity, t.Name, fmt.Sprintf(
					"%s %q passes model-controlled %q to %s (unsafe deserialization / dynamic code loading).", t.Noun(), t.Name, p, s.what)))
				return
			}
		})
	}
	return out
}

func isStringLiteral(s string) bool {
	s = strings.TrimSpace(s)
	return len(s) >= 2 && (s[0] == '"' || s[0] == '\'' || s[0] == '`') && s[len(s)-1] == s[0]
}
