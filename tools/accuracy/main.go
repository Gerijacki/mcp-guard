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
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/Gerijacki/mcp-guard/internal/finding"
	"github.com/Gerijacki/mcp-guard/internal/rules"
	"github.com/Gerijacki/mcp-guard/internal/scanner"
)

type corpus struct {
	Repos []repo `yaml:"repos"`
}

type repo struct {
	Name   string `yaml:"name"`
	Commit string `yaml:"commit"`
	Expect counts `yaml:"expect"`
}

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
		got, details, err := scan(dir)
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
				failures = append(failures, fmt.Sprintf("%s: expected %s, got %s\n%s", r.Name, describe(r.Expect), describe(got), details))
			}
		}
		fmt.Fprintf(&report, "| [%s](https://github.com/%s) | %d | %d | %s | %s |\n", r.Name, r.Name, got.Tools, got.Configs, findingsText(got.Findings), status)
		fmt.Printf("%-36s tools=%-4d configs=%-2d findings=%-28s %s\n", r.Name, got.Tools, got.Configs, findingsText(got.Findings), status)
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
		return os.WriteFile(corpusPath, append([]byte(header), out...), 0o644)
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
	if err := git(dir, "fetch", "-q", "--depth", "1", "origin", ref); err != nil {
		return err
	}
	return git(dir, "checkout", "-q", "--force", "FETCH_HEAD")
}

func git(dir string, args ...string) error {
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Stdout, cmd.Stderr = io.Discard, os.Stderr
	return cmd.Run()
}

// scan runs mcp-guard with the CLI defaults and returns the counts plus a listing of the
// findings for failure messages.
func scan(dir string) (counts, string, error) {
	res, err := scanner.Scan(scanner.Options{Root: dir, Rules: rules.Builtin(), MinSeverity: finding.Low})
	if err != nil {
		return counts{}, "", err
	}
	c := counts{Tools: res.ToolsFound, Configs: res.ConfigsFound, Findings: map[string]int{}}
	var lines []string
	for _, f := range res.Findings {
		c.Findings[f.RuleID]++
		rel, _ := filepath.Rel(dir, filepath.FromSlash(f.File))
		lines = append(lines, fmt.Sprintf("    %s %s:%d %s", f.RuleID, filepath.ToSlash(rel), f.Line, f.Message))
	}
	return c, strings.Join(lines, "\n"), nil
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
