// Package cli implements the mcp-guard command line: scan, tools, rules and version.
package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/Gerijacki/mcp-guard/internal/baseline"
	"github.com/Gerijacki/mcp-guard/internal/config"
	"github.com/Gerijacki/mcp-guard/internal/finding"
	"github.com/Gerijacki/mcp-guard/internal/lock"
	"github.com/Gerijacki/mcp-guard/internal/report"
	"github.com/Gerijacki/mcp-guard/internal/rules"
	"github.com/Gerijacki/mcp-guard/internal/scanner"
)

// version is set at build time with -ldflags "-X github.com/Gerijacki/mcp-guard/internal/cli.version=v1.2.3".
var version = "dev"

// Exit codes.
const (
	ExitOK       = 0 // no findings at or above --fail-on
	ExitFindings = 1 // findings at or above --fail-on
	ExitError    = 2 // usage or runtime error
)

const usage = `mcp-guard: security scanner for MCP (Model Context Protocol) servers

Usage:
  mcp-guard scan [path] [flags]   Scan a directory or file (default: current directory)
  mcp-guard tools [path] [flags]  Show the MCP tools and client configs that were extracted
  mcp-guard lock [path] [flags]   Record the tool definitions and server commands (for scan --lock)
  mcp-guard rules [list]          List available rules
  mcp-guard rules explain <ID>    Show details and remediation for a rule
  mcp-guard version               Print the version

Run 'mcp-guard scan -h' for scan flags.
`

// Version returns the build version.
func Version() string {
	if version != "dev" {
		return version
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		return bi.Main.Version
	}
	return version
}

// Run executes the CLI and returns the process exit code.
func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return ExitError
	}
	switch args[0] {
	case "scan":
		return runScan(args[1:], stdout, stderr)
	case "tools":
		return runTools(args[1:], stdout, stderr)
	case "lock":
		return runLock(args[1:], stdout, stderr)
	case "rules":
		return runRules(args[1:], stdout, stderr)
	case "version", "--version", "-v":
		fmt.Fprintln(stdout, "mcp-guard", Version())
		return ExitOK
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return ExitOK
	}
	fmt.Fprintf(stderr, "unknown command %q\n\n%s", args[0], usage)
	return ExitError
}

// listFlag is a repeatable, comma-separated string flag.
type listFlag []string

func (l *listFlag) String() string { return strings.Join(*l, ",") }

func (l *listFlag) Set(v string) error {
	for _, part := range strings.Split(v, ",") {
		if part = strings.TrimSpace(part); part != "" {
			*l = append(*l, part)
		}
	}
	return nil
}

type scanFlags struct {
	format, output, failOn, minSeverity, configPath string
	baselinePath, writeBaseline, changedSince       string
	lockPath                                        string
	rules, disable, ignore, also                    listFlag
	noColor, includeTests, strict                   bool
	requireReason, warnUnused                       bool
	workers                                         int
	maxFileSize                                     int64
	timeout                                         time.Duration
}

// parseInterleaved parses flags that may appear before or after positional arguments.
func parseInterleaved(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		if fs.NArg() == 0 {
			return pos, nil
		}
		pos = append(pos, fs.Arg(0))
		args = fs.Args()[1:]
	}
}

func runScan(args []string, stdout, stderr io.Writer) int {
	var sf scanFlags
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&sf.format, "format", "text", "output format: text, json, sarif, markdown or github (workflow annotations)")
	fs.StringVar(&sf.format, "f", "text", "shorthand for --format")
	fs.StringVar(&sf.output, "output", "", "write the report to this file instead of stdout")
	fs.StringVar(&sf.output, "o", "", "shorthand for --output")
	fs.StringVar(&sf.failOn, "fail-on", "", "exit with code 1 if a finding has at least this severity: critical, high, medium, low, info or none (default high)")
	fs.StringVar(&sf.minSeverity, "min-severity", "", "hide findings below this severity (default low; use info to see quality hints)")
	fs.StringVar(&sf.configPath, "config", "", "config file (default: .mcp-guard.yaml in the scanned directory)")
	fs.Var(&sf.rules, "rules", "custom rule file or directory (repeatable)")
	fs.Var(&sf.disable, "disable", "rule IDs to disable, comma-separated (repeatable)")
	fs.Var(&sf.ignore, "ignore", "glob of paths to skip, relative to the scanned path (repeatable)")
	fs.BoolVar(&sf.noColor, "no-color", false, "disable colored output (also honors NO_COLOR)")
	fs.BoolVar(&sf.includeTests, "include-tests", false, "also scan test files and directories (tests/, *_test.go, *.test.ts, ...)")
	fs.StringVar(&sf.lockPath, "lock", "", "check tool definitions and server launch commands against this lock file (see 'mcp-guard lock')")
	fs.Var(&sf.also, "also", "write another report from the same scan, as format=path, e.g. sarif=out.sarif (repeatable)")
	fs.BoolVar(&sf.strict, "strict", false, "exit with code 2 when any file could not be analyzed (unreadable, timed out, internal error)")
	fs.StringVar(&sf.baselinePath, "baseline", "", "only report findings that are not in this baseline file (see --write-baseline)")
	fs.StringVar(&sf.writeBaseline, "write-baseline", "", "write the current findings to this baseline file and exit 0")
	fs.StringVar(&sf.changedSince, "changed-since", "", "only scan files changed since this git ref (plus untracked files)")
	fs.BoolVar(&sf.requireReason, "require-ignore-reason", false, "ignore 'mcp-guard:ignore' comments that give no reason")
	fs.BoolVar(&sf.warnUnused, "warn-unused-ignores", false, "warn about 'mcp-guard:ignore' comments that suppress nothing")
	fs.IntVar(&sf.workers, "workers", 0, "number of files analyzed in parallel (default: number of CPUs)")
	fs.Int64Var(&sf.maxFileSize, "max-file-size", 0, "skip files larger than this many bytes (default 1048576)")
	fs.DurationVar(&sf.timeout, "timeout", 0, "analysis time budget per file (default 10s)")
	fs.Usage = func() {
		fmt.Fprint(stderr, "Usage: mcp-guard scan [path] [flags]\n\nFlags:\n")
		fs.PrintDefaults()
	}
	pos, err := parseInterleaved(fs, args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitOK
		}
		return ExitError
	}
	if len(pos) > 1 {
		fmt.Fprintln(stderr, "error: scan accepts a single path")
		return ExitError
	}
	root := "."
	if len(pos) == 1 {
		root = pos[0]
	}
	code, err := scan(root, sf, stdout, stderr)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return ExitError
	}
	return code
}

func scan(root string, sf scanFlags, stdout, stderr io.Writer) (int, error) {
	info, err := os.Stat(root)
	if err != nil {
		return 0, err
	}
	cfgPath := sf.configPath
	if cfgPath == "" {
		dir := root
		if !info.IsDir() {
			dir = filepath.Dir(root)
		}
		cfgPath = config.FindUp(dir)
	}
	cfg := &config.Config{}
	if cfgPath != "" {
		if cfg, err = config.Load(cfgPath); err != nil {
			return 0, err
		}
	}

	failOnName := firstNonEmpty(sf.failOn, cfg.FailOn, "high")
	failOn, failNever := finding.Critical, strings.EqualFold(failOnName, "none")
	if !failNever {
		if failOn, err = finding.ParseSeverity(failOnName); err != nil {
			return 0, fmt.Errorf("--fail-on: %w", err)
		}
	}
	minSev, err := finding.ParseSeverity(firstNonEmpty(sf.minSeverity, cfg.MinSeverity, "low"))
	if err != nil {
		return 0, fmt.Errorf("--min-severity: %w", err)
	}

	all, err := loadRules(append(append([]string{}, cfg.Rules...), sf.rules...))
	if err != nil {
		return 0, err
	}
	if len(cfg.Extend) > 0 {
		ext := map[string]rules.Extension{}
		for id, e := range cfg.Extend {
			ext[strings.ToUpper(strings.TrimSpace(id))] = rules.Extension{Sinks: e.Sinks, Sanitizers: e.Sanitizers}
		}
		if all, err = rules.WithExtensions(all, ext); err != nil {
			return 0, fmt.Errorf("%s: %w", cfg.Path, err)
		}
	}
	if lockPath := firstNonEmpty(sf.lockPath, cfg.Lock); lockPath != "" {
		l, err := lock.Load(lockPath)
		if err != nil {
			return 0, err
		}
		all = rules.WithLock(all, l, root)
	}
	known := map[string]bool{}
	for _, r := range all {
		known[r.Meta().ID] = true
	}
	disabled := map[string]bool{}
	for _, id := range append(append([]string{}, cfg.Disable...), sf.disable...) {
		id = strings.ToUpper(strings.TrimSpace(id))
		if !known[id] {
			return 0, fmt.Errorf("cannot disable unknown rule %q", id)
		}
		disabled[id] = true
	}
	overrides := map[string]finding.Severity{}
	for id, name := range cfg.Severity {
		sev, err := finding.ParseSeverity(name)
		if err != nil {
			return 0, fmt.Errorf("%s: severity for %s: %w", cfg.Path, id, err)
		}
		overrides[strings.ToUpper(id)] = sev
	}

	var pathRules []scanner.PathRule
	for _, o := range cfg.Overrides {
		pr := scanner.PathRule{Glob: o.Path, Disabled: map[string]bool{}}
		for _, id := range o.Disable {
			id = strings.ToUpper(strings.TrimSpace(id))
			if !known[id] {
				return 0, fmt.Errorf("%s: override for %q disables unknown rule %q", cfg.Path, o.Path, id)
			}
			pr.Disabled[id] = true
		}
		pathRules = append(pathRules, pr)
	}
	var only map[string]bool
	if sf.changedSince != "" {
		if only, err = changedFiles(root, sf.changedSince); err != nil {
			return 0, err
		}
	}

	res, err := scanner.Scan(scanner.Options{
		Root:                root,
		Rules:               all,
		Ignore:              append(append([]string{}, cfg.Ignore...), sf.ignore...),
		Disabled:            disabled,
		SeverityOverrides:   overrides,
		MinSeverity:         minSev,
		IncludeTests:        sf.includeTests || cfg.IncludeTests,
		MaxFileSize:         sf.maxFileSize,
		Workers:             sf.workers,
		FileTimeout:         sf.timeout,
		Only:                only,
		PathRules:           pathRules,
		RequireIgnoreReason: sf.requireReason || cfg.RequireIgnoreReason,
		WarnUnusedIgnores:   sf.warnUnused || cfg.WarnUnusedIgnores,
	})
	if err != nil {
		return 0, err
	}

	if sf.writeBaseline != "" {
		if err := baseline.Save(sf.writeBaseline, res.Findings); err != nil {
			return 0, err
		}
		fmt.Fprintf(stderr, "baseline: wrote %d findings to %s\n", len(res.Findings), sf.writeBaseline)
		return ExitOK, nil
	}
	if sf.baselinePath != "" {
		b, err := baseline.Load(sf.baselinePath)
		if err != nil {
			return 0, err
		}
		var gone int
		res.Findings, res.Baselined, gone = b.Filter(res.Findings)
		if sf.changedSince == "" { // with a partial scan, missing entries just mean "not scanned"
			res.Fixed = gone
			if gone > 0 {
				fmt.Fprintf(stderr, "baseline: %d entries no longer occur; refresh it with --write-baseline\n", gone)
			}
		}
	}

	out := stdout
	color := !sf.noColor && os.Getenv("NO_COLOR") == "" && isTerminal(stdout)
	if sf.output != "" {
		fh, err := os.Create(sf.output)
		if err != nil {
			return 0, err
		}
		defer fh.Close()
		out, color = fh, false
	}
	if err := report.Write(out, sf.format, res, report.Options{Version: Version(), Color: color}); err != nil {
		return 0, err
	}

	for _, spec := range sf.also {
		format, path, ok := strings.Cut(spec, "=")
		if !ok || format == "" || path == "" {
			return 0, fmt.Errorf("--also %q: want format=path, e.g. sarif=out.sarif", spec)
		}
		if err := writeReport(path, format, res); err != nil {
			return 0, err
		}
	}
	for _, w := range res.Warnings {
		fmt.Fprintln(stderr, "warning:", w)
	}
	if !failNever {
		for _, f := range res.Findings {
			if f.Severity >= failOn {
				return ExitFindings, nil
			}
		}
	}
	if sf.strict && (res.Skipped.Unreadable+res.Skipped.TimedOut+res.Skipped.Failed) > 0 {
		return ExitError, nil
	}
	return ExitOK, nil
}

// changedFiles returns the absolute, slash-separated paths of the files that differ from ref
// in the git work tree containing root, plus untracked files.
func changedFiles(root, ref string) (map[string]bool, error) {
	dir := root
	if info, err := os.Stat(root); err == nil && !info.IsDir() {
		dir = filepath.Dir(root)
	}
	git := func(args ...string) ([]string, error) {
		out, err := exec.Command("git", append([]string{"-C", dir}, args...)...).Output()
		if err != nil {
			return nil, fmt.Errorf("--changed-since: git %s: %w", strings.Join(args, " "), err)
		}
		return strings.Split(strings.TrimSpace(string(out)), "\n"), nil
	}
	top, err := git("rev-parse", "--show-toplevel")
	if err != nil {
		return nil, err
	}
	changed, err := git("diff", "--name-only", "--diff-filter=d", ref, "--")
	if err != nil {
		return nil, err
	}
	untracked, err := git("ls-files", "--others", "--exclude-standard")
	if err != nil {
		return nil, err
	}
	only := map[string]bool{}
	for _, name := range append(changed, untracked...) {
		if name = strings.TrimSpace(name); name != "" {
			only[filepath.ToSlash(filepath.Join(top[0], filepath.FromSlash(name)))] = true
		}
	}
	return only, nil
}

func writeReport(path, format string, res *scanner.Result) error {
	fh, err := os.Create(path)
	if err != nil {
		return err
	}
	defer fh.Close()
	return report.Write(fh, format, res, report.Options{Version: Version()})
}

func loadRules(customPaths []string) ([]rules.Rule, error) {
	all := rules.Builtin()
	seen := map[string]bool{}
	for _, r := range all {
		seen[r.Meta().ID] = true
	}
	for _, p := range customPaths {
		custom, err := rules.LoadCustom(p)
		if err != nil {
			return nil, fmt.Errorf("loading custom rules: %w", err)
		}
		for _, r := range custom {
			id := r.Meta().ID
			if seen[id] {
				return nil, fmt.Errorf("duplicate rule id %q in %s", id, p)
			}
			seen[id] = true
			all = append(all, r)
		}
	}
	return all, nil
}

func runRules(args []string, stdout, stderr io.Writer) int {
	var custom listFlag
	fs := flag.NewFlagSet("rules", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Var(&custom, "rules", "also load custom rules from this file or directory (repeatable)")
	pos, err := parseInterleaved(fs, args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitOK
		}
		return ExitError
	}
	all, err := loadRules(custom)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return ExitError
	}
	if len(pos) == 0 || pos[0] == "list" {
		tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "ID\tSEVERITY\tNAME\tSUMMARY")
		for _, r := range all {
			m := r.Meta()
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", m.ID, m.Severity, m.Name, m.Summary)
		}
		tw.Flush()
		return ExitOK
	}
	if pos[0] != "explain" || len(pos) != 2 {
		fmt.Fprintln(stderr, "usage: mcp-guard rules [list] | mcp-guard rules explain <ID>")
		return ExitError
	}
	id := strings.ToUpper(pos[1])
	for _, r := range all {
		m := r.Meta()
		if m.ID != id {
			continue
		}
		fmt.Fprintf(stdout, "%s  %s  (default severity: %s)\n\n%s\n\n", m.ID, m.Name, m.Severity, m.Summary)
		if m.Description != "" {
			fmt.Fprintf(stdout, "Why it matters:\n  %s\n\n", m.Description)
		}
		if m.Remediation != "" {
			fmt.Fprintf(stdout, "How to fix:\n  %s\n\n", m.Remediation)
		}
		if len(m.CWE) > 0 {
			fmt.Fprintf(stdout, "References: %s\n", strings.Join(m.CWE, ", "))
		}
		if len(m.OWASP) > 0 {
			fmt.Fprintf(stdout, "OWASP: %s\n", strings.Join(m.OWASP, ", "))
		}
		if u := m.Help(); u != "" {
			fmt.Fprintf(stdout, "Docs: %s\n", u)
		}
		return ExitOK
	}
	fmt.Fprintf(stderr, "unknown rule %q\n", id)
	return ExitError
}

func firstNonEmpty(xs ...string) string {
	for _, x := range xs {
		if strings.TrimSpace(x) != "" {
			return x
		}
	}
	return ""
}

func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}
