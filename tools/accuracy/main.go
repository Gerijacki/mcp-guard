// Command accuracy runs mcp-guard against real MCP repositories and compares the result
// with the expectations recorded in benchmark/corpus.yaml.
//
//	go run ./tools/accuracy            # pinned commits: exact match required (CI gate)
//	go run ./tools/accuracy -update    # rewrite expectations from the current results
//	go run ./tools/accuracy -latest    # default branches: canary for SDK changes
//
// In -latest mode only a large drop in extracted tools fails the run (it means an SDK
// changed how tools are registered); finding changes are reported for information.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/Gerijacki/mcp-guard/internal/finding"
	"github.com/Gerijacki/mcp-guard/internal/rules"
	"github.com/Gerijacki/mcp-guard/internal/scanner"
)

type corpus struct {
	// MinPrecision is the lowest per-rule precision (tp / (tp+fp) over the labelled
	// findings of all repositories) CI accepts. Default 0.9.
	MinPrecision float64 `yaml:"min-precision,omitempty"`
	Repos        []repo  `yaml:"repos"`
}

type repo struct {
	Name   string `yaml:"name"`
	Commit string `yaml:"commit"`
	Expect counts `yaml:"expect"`
	// Labels is the ground truth for every finding: a human decided whether it is a real
	// problem (tp) or a false positive (fp). The counts above only detect change; labels
	// are what makes precision measurable.
	Labels []label `yaml:"labels,omitempty"`
	// KnownGaps are vulnerabilities we know exist but the scanner misses (false negatives).
	// If one starts being reported, the run fails so it is moved into Labels as a tp.
	KnownGaps []gap `yaml:"known-gaps,omitempty"`
}

// label classifies one finding. Findings are matched on rule, file and tool, not on the
// line number, so the entry survives unrelated edits.
type label struct {
	Rule  string `yaml:"rule"`
	File  string `yaml:"file"`
	Tool  string `yaml:"tool,omitempty"`
	Label string `yaml:"label"` // tp | fp | todo (written by -update, must be reviewed)
	Note  string `yaml:"note,omitempty"`
}

type gap struct {
	Rule string `yaml:"rule"`
	File string `yaml:"file"`
	Tool string `yaml:"tool,omitempty"`
	Why  string `yaml:"why"`
}

// found is one scanner finding in a repository.
type found struct {
	Rule, File, Tool string
	Line             int
	Message          string
}

func (f found) key() string { return f.Rule + "|" + f.File + "|" + f.Tool }
func (l label) key() string { return l.Rule + "|" + l.File + "|" + l.Tool }
func (g gap) key() string   { return g.Rule + "|" + g.File + "|" + g.Tool }

type counts struct {
	Tools    int            `yaml:"tools"`
	Configs  int            `yaml:"configs"`
	Findings map[string]int `yaml:"findings"`
}

const header = `# Real-world accuracy benchmark. Run with: go run ./tools/accuracy
#
# Each entry pins a public MCP repository at a commit and records what mcp-guard is
# expected to find there with default settings (tests skipped, min severity low).
# A change in any number fails CI: if the change is an intended improvement, review
# the new findings and refresh the expectations with: go run ./tools/accuracy -update
#
# Every finding must be labelled tp (real problem) or fp (false positive) with a note;
# -update adds new findings as "todo" and fails until a human reviews them. CI gates the
# per-rule precision on these labels. known-gaps lists real vulnerabilities we miss.
`

// latestToolRatio is the share of the pinned tool count that the default branch must
// still yield in -latest mode.
const latestToolRatio = 0.8

func main() {
	corpusPath := flag.String("corpus", filepath.Join("benchmark", "corpus.yaml"), "corpus file")
	workdir := flag.String("workdir", filepath.Join(os.TempDir(), "mcp-guard-accuracy"), "where repositories are cloned")
	latest := flag.Bool("latest", false, "scan default branches instead of pinned commits")
	update := flag.Bool("update", false, "rewrite the expectations with the current results")
	summary := flag.String("summary", os.Getenv("GITHUB_STEP_SUMMARY"), "append a markdown report to this file")
	flag.Parse()

	if err := run(*corpusPath, *workdir, *latest, *update, *summary); err != nil {
		fmt.Fprintln(os.Stderr, "accuracy:", err)
		os.Exit(1)
	}
}

func run(corpusPath, workdir string, latest, update bool, summaryPath string) error {
	b, err := os.ReadFile(corpusPath)
	if err != nil {
		return err
	}
	var c corpus
	if err := yaml.Unmarshal(b, &c); err != nil {
		return fmt.Errorf("%s: %w", corpusPath, err)
	}

	var report strings.Builder
	mode := "pinned commits"
	if latest {
		mode = "default branches (canary)"
	}
	fmt.Fprintf(&report, "## mcp-guard accuracy benchmark: %s\n\n| Repository | Tools | Configs | Findings | Status |\n|---|---|---|---|---|\n", mode)

	minPrecision := c.MinPrecision
	if minPrecision == 0 {
		minPrecision = 0.9
	}
	prec := tally{}
	var failures []string
	for i := range c.Repos {
		r := &c.Repos[i]
		dir := filepath.Join(workdir, strings.ReplaceAll(r.Name, "/", "_"))
		ref := r.Commit
		if latest {
			ref = "HEAD"
		}
		if err := checkout(dir, "https://github.com/"+r.Name+".git", ref); err != nil {
			return fmt.Errorf("%s: %w", r.Name, err)
		}
		got, all, err := scan(dir)
		if err != nil {
			return fmt.Errorf("%s: %w", r.Name, err)
		}

		status := "ok"
		switch {
		case update:
			r.Expect = got
			status = "updated"
		case latest:
			if float64(got.Tools) < latestToolRatio*float64(r.Expect.Tools) {
				status = "FAIL: tool extraction dropped"
				failures = append(failures, fmt.Sprintf("%s: %d tools extracted on the default branch, %d at the pinned commit", r.Name, got.Tools, r.Expect.Tools))
			} else if !equal(got, r.Expect) {
				status = "changed (informational)"
			}
		default:
			if !equal(got, r.Expect) {
				status = "FAIL"
				failures = append(failures, fmt.Sprintf("%s: expected %s, got %s\n%s", r.Name, describe(r.Expect), describe(got), listing(all)))
			}
		}
		if !latest {
			if problems := reconcile(r, all, prec, update); len(problems) > 0 {
				status = "FAIL: labels"
				failures = append(failures, problems...)
			}
		}
		fmt.Fprintf(&report, "| [%s](https://github.com/%s) | %d | %d | %s | %s |\n", r.Name, r.Name, got.Tools, got.Configs, findingsText(got.Findings), status)
		fmt.Printf("%-36s tools=%-4d configs=%-2d findings=%-28s %s\n", r.Name, got.Tools, got.Configs, findingsText(got.Findings), status)
	}

	if !latest {
		text, bad := precisionReport(prec, minPrecision)
		report.WriteString(text)
		if !update {
			failures = append(failures, bad...)
		}
	}
	if summaryPath != "" {
		if err := appendFile(summaryPath, report.String()); err != nil {
			return err
		}
	}
	if update {
		out, err := yaml.Marshal(c)
		if err != nil {
			return err
		}
		if err := os.WriteFile(corpusPath, append([]byte(header), out...), 0o644); err != nil {
			return err
		}
		for _, r := range c.Repos {
			for _, l := range r.Labels {
				if l.Label == "todo" {
					return fmt.Errorf("%s: new finding %s %s written as \"todo\": review it and set label to tp or fp (with a note) before committing", r.Name, l.Rule, l.File)
				}
			}
		}
		return nil
	}
	if len(failures) > 0 {
		return errors.New("accuracy regression:\n" + strings.Join(failures, "\n"))
	}
	return nil
}

// checkout fetches ref (a commit SHA or HEAD) with depth 1 into dir.
func checkout(dir, url, ref string) error {
	if _, err := os.Stat(filepath.Join(dir, ".git")); err != nil {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
		if err := git(dir, "init", "-q"); err != nil {
			return err
		}
		if err := git(dir, "remote", "add", "origin", url); err != nil {
			return err
		}
	}
	// A pinned commit that is already present needs no network round trip.
	if shaRe.MatchString(ref) && gitQuiet(dir, "cat-file", "-e", ref+"^{commit}") == nil {
		return git(dir, "checkout", "-q", "--force", ref)
	}
	if err := git(dir, "fetch", "-q", "--depth", "1", "origin", ref); err != nil {
		return err
	}
	return git(dir, "checkout", "-q", "--force", "FETCH_HEAD")
}

var shaRe = regexp.MustCompile(`^[0-9a-f]{40}$`)

// gitQuiet runs git and discards all output; only the exit status matters.
func gitQuiet(dir string, args ...string) error {
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	return cmd.Run()
}

func git(dir string, args ...string) error {
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Stdout, cmd.Stderr = io.Discard, os.Stderr
	return cmd.Run()
}

// scan runs mcp-guard with the CLI defaults and returns the counts plus a listing of the
// findings for failure messages.
func scan(dir string) (counts, []found, error) {
	res, err := scanner.Scan(scanner.Options{Root: dir, Rules: rules.Builtin(), MinSeverity: finding.Low})
	if err != nil {
		return counts{}, nil, err
	}
	c := counts{Tools: res.ToolsFound, Configs: res.ConfigsFound, Findings: map[string]int{}}
	var all []found
	for _, f := range res.Findings {
		c.Findings[f.RuleID]++
		rel, _ := filepath.Rel(dir, filepath.FromSlash(f.File))
		all = append(all, found{Rule: f.RuleID, File: filepath.ToSlash(rel), Tool: f.Tool, Line: f.Line, Message: f.Message})
	}
	return c, all, nil
}

func listing(fs []found) string {
	lines := make([]string, len(fs))
	for i, f := range fs {
		lines[i] = fmt.Sprintf("    %s %s:%d %s", f.Rule, f.File, f.Line, f.Message)
	}
	return strings.Join(lines, "\n")
}

// tally holds the labelled outcome per rule across all repositories.
type tally map[string]*struct{ tp, fp int }

func (t tally) add(rule, lbl string) {
	if t[rule] == nil {
		t[rule] = &struct{ tp, fp int }{}
	}
	switch lbl {
	case "tp":
		t[rule].tp++
	case "fp":
		t[rule].fp++
	}
}

// reconcile matches findings against labels (one label consumes one finding with the same
// key). It returns problems: findings without a label, labels with no finding, labels still
// "todo", and known gaps that are now detected. With update it instead rewrites the labels:
// stale ones are dropped and unlabelled findings get a "todo" stub.
func reconcile(r *repo, fs []found, t tally, update bool) []string {
	var problems []string
	pool := map[string][]int{} // key -> indexes into r.Labels
	for i, l := range r.Labels {
		pool[l.key()] = append(pool[l.key()], i)
	}
	used := make([]bool, len(r.Labels))
	var stubs []label
	for _, f := range fs {
		if idx := pool[f.key()]; len(idx) > 0 {
			i := idx[0]
			pool[f.key()] = idx[1:]
			used[i] = true
			continue
		}
		stubs = append(stubs, label{Rule: f.Rule, File: f.File, Tool: f.Tool, Label: "todo", Note: f.Message})
		problems = append(problems, fmt.Sprintf("%s: unlabelled finding %s %s:%d %s", r.Name, f.Rule, f.File, f.Line, f.Message))
	}
	kept := r.Labels[:0:0]
	for i, l := range r.Labels {
		if !used[i] {
			problems = append(problems, fmt.Sprintf("%s: stale label for %s %s (no such finding any more)", r.Name, l.Rule, l.File))
			continue
		}
		if l.Label != "tp" && l.Label != "fp" {
			problems = append(problems, fmt.Sprintf("%s: label for %s %s is %q: review it as tp or fp", r.Name, l.Rule, l.File, l.Label))
		}
		t.add(l.Rule, l.Label)
		kept = append(kept, l)
	}
	for _, g := range r.KnownGaps {
		for _, f := range fs {
			if f.key() == g.key() {
				problems = append(problems, fmt.Sprintf("%s: known gap now detected (%s %s): move it into labels as tp", r.Name, g.Rule, g.File))
			}
		}
	}
	if update {
		r.Labels = append(append([]label(nil), kept...), stubs...)
		return nil
	}
	return problems
}

func precisionReport(t tally, min float64) (text string, failures []string) {
	rules := make([]string, 0, len(t))
	for k := range t {
		rules = append(rules, k)
	}
	sort.Strings(rules)
	var sb strings.Builder
	sb.WriteString("\n| Rule | TP | FP | Precision |\n|---|---|---|---|\n")
	for _, id := range rules {
		c := t[id]
		p := 1.0
		if n := c.tp + c.fp; n > 0 {
			p = float64(c.tp) / float64(n)
		}
		fmt.Fprintf(&sb, "| %s | %d | %d | %.0f%% |\n", id, c.tp, c.fp, p*100)
		fmt.Printf("  %-8s tp=%-3d fp=%-3d precision=%.0f%%\n", id, c.tp, c.fp, p*100)
		if p < min {
			failures = append(failures, fmt.Sprintf("precision of %s is %.0f%%, below the %.0f%% floor", id, p*100, min*100))
		}
	}
	return sb.String(), failures
}

func equal(a, b counts) bool {
	if a.Tools != b.Tools || a.Configs != b.Configs || len(a.Findings) != len(b.Findings) {
		return false
	}
	for k, v := range a.Findings {
		if b.Findings[k] != v {
			return false
		}
	}
	return true
}

func describe(c counts) string {
	return fmt.Sprintf("tools=%d configs=%d findings=%s", c.Tools, c.Configs, findingsText(c.Findings))
}

func findingsText(m map[string]int) string {
	if len(m) == 0 {
		return "none"
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = fmt.Sprintf("%s×%d", k, m[k])
	}
	return strings.Join(parts, " ")
}

func appendFile(path, text string) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(text + "\n")
	return err
}
