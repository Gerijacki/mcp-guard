package rules

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/Gerijacki/mcp-guard/internal/finding"
	"github.com/Gerijacki/mcp-guard/internal/source"
)

// CustomSpec is the YAML schema of a user-defined rule. See docs/custom-rules.md.
type CustomSpec struct {
	ID          string   `yaml:"id"`
	Name        string   `yaml:"name"`
	Severity    string   `yaml:"severity"`
	Message     string   `yaml:"message"`
	Description string   `yaml:"description"`
	Remediation string   `yaml:"remediation"`
	CWE         []string `yaml:"cwe"`
	OWASP       []string `yaml:"owasp"`
	HelpURL     string   `yaml:"help-url"`
	Languages   []string `yaml:"languages"`
	// Scope is where the pattern is matched: "file" (every line, default), "tool-body"
	// (statements inside tool handlers) or "tool-description" (tool/parameter descriptions).
	Scope   string `yaml:"scope"`
	Pattern string `yaml:"pattern"`
	// RequiresTaintedInput (tool-body only) reports a match only when the statement also
	// uses a value derived from a tool parameter.
	RequiresTaintedInput bool     `yaml:"requires-tainted-input"`
	Unless               []string `yaml:"unless"`
}

type customFile struct {
	Rules []CustomSpec `yaml:"rules"`
}

type customRule struct {
	meta      Meta
	message   string
	langs     map[source.Language]bool
	scope     string
	pattern   *regexp.Regexp
	unless    []*regexp.Regexp
	needTaint bool
}

var customIDRe = regexp.MustCompile(`^[A-Z][A-Z0-9_-]{2,31}$`)

// LoadCustom loads custom rules from a YAML file or from every *.yml/*.yaml file under a directory.
func LoadCustom(path string) ([]Rule, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	var files []string
	if info.IsDir() {
		err = filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if ext := strings.ToLower(filepath.Ext(p)); !d.IsDir() && (ext == ".yml" || ext == ".yaml") {
				files = append(files, p)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	} else {
		files = []string{path}
	}
	var out []Rule
	for _, file := range files {
		b, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}
		var cf customFile
		if err := yaml.Unmarshal(b, &cf); err != nil {
			return nil, fmt.Errorf("%s: %w", file, err)
		}
		for i, spec := range cf.Rules {
			r, err := CompileCustom(spec)
			if err != nil {
				return nil, fmt.Errorf("%s: rule #%d: %w", file, i+1, err)
			}
			out = append(out, r)
		}
	}
	return out, nil
}

// CompileCustom validates a spec and turns it into a Rule.
func CompileCustom(s CustomSpec) (Rule, error) {
	if !customIDRe.MatchString(s.ID) {
		return nil, fmt.Errorf("invalid id %q: use 3-32 upper-case letters, digits, '-' or '_'", s.ID)
	}
	if strings.HasPrefix(s.ID, "MCPG") {
		return nil, fmt.Errorf("id %q: the MCPG prefix is reserved for built-in rules", s.ID)
	}
	if s.Pattern == "" {
		return nil, errors.New("pattern is required")
	}
	re, err := regexp.Compile(s.Pattern)
	if err != nil {
		return nil, fmt.Errorf("pattern: %w", err)
	}
	sev := finding.Medium
	if s.Severity != "" {
		if sev, err = finding.ParseSeverity(s.Severity); err != nil {
			return nil, err
		}
	}
	scope := s.Scope
	if scope == "" {
		scope = "file"
	}
	switch scope {
	case "file", "tool-body", "tool-description":
	default:
		return nil, fmt.Errorf("scope %q: want file, tool-body or tool-description", scope)
	}
	if s.RequiresTaintedInput && scope != "tool-body" {
		return nil, errors.New("requires-tainted-input is only valid with scope: tool-body")
	}
	r := &customRule{scope: scope, pattern: re, needTaint: s.RequiresTaintedInput, message: s.Message}
	if len(s.Languages) > 0 {
		r.langs = map[source.Language]bool{}
		for _, l := range s.Languages {
			lang, ok := source.ParseLanguage(l)
			if !ok {
				return nil, fmt.Errorf("unknown language %q", l)
			}
			r.langs[lang] = true
		}
	}
	for _, u := range s.Unless {
		ure, err := regexp.Compile(u)
		if err != nil {
			return nil, fmt.Errorf("unless %q: %w", u, err)
		}
		r.unless = append(r.unless, ure)
	}
	name := s.Name
	if name == "" {
		name = strings.ToLower(s.ID)
	}
	if r.message == "" {
		r.message = s.Description
	}
	if r.message == "" {
		r.message = "Matched custom rule " + s.ID
	}
	r.meta = Meta{
		ID: s.ID, Name: name, Severity: sev, Summary: firstLine(s.Description, r.message),
		Description: s.Description, Remediation: s.Remediation, CWE: s.CWE, OWASP: s.OWASP, HelpURL: s.HelpURL,
	}
	return r, nil
}

func (r *customRule) Meta() Meta { return r.meta }

func (r *customRule) Check(f *source.File) []finding.Finding {
	if r.langs != nil && !r.langs[f.Language] {
		return nil
	}
	var out []finding.Finding
	emit := func(n int, tool, param string) {
		msg := strings.NewReplacer("{tool}", tool, "{param}", param).Replace(r.message)
		out = append(out, newFinding(r.meta, f, n, r.meta.Severity, tool, msg))
	}
	switch r.scope {
	case "file":
		for i, line := range f.Lines {
			if r.pattern.MatchString(line) && !r.excluded(line) {
				emit(i+1, "", "")
			}
		}
	case "tool-body":
		for _, t := range toolBodies(f) {
			walkTaint(f, t, nil, func(st source.Stmt, taint *taintSet) {
				loc := r.pattern.FindStringIndex(st.Text)
				if loc == nil || r.excluded(st.Text) {
					return
				}
				p := taint.find(st.Text[loc[0]:])
				if r.needTaint && p == "" {
					return
				}
				emit(st.Line, t.Name, p)
			})
		}
	case "tool-description":
		for _, t := range f.Tools {
			text := strings.Join(append([]string{t.Description}, t.ParamDescriptions...), "\n")
			if r.pattern.MatchString(text) && !r.excluded(text) {
				n := t.DescriptionLine
				if n == 0 {
					n = t.Line
				}
				emit(n, t.Name, "")
			}
		}
	}
	return out
}

func (r *customRule) excluded(text string) bool {
	for _, u := range r.unless {
		if u.MatchString(text) {
			return true
		}
	}
	return false
}

func firstLine(xs ...string) string {
	for _, x := range xs {
		if x = strings.TrimSpace(x); x != "" {
			if i := strings.IndexByte(x, '\n'); i >= 0 {
				return x[:i]
			}
			return x
		}
	}
	return ""
}
