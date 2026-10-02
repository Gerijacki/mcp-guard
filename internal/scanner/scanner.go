// Package scanner walks a directory, loads supported files, extracts MCP tools and
// runs the rules over them, applying suppressions, ignores and severity overrides.
package scanner

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Gerijacki/mcp-guard/internal/extract"
	"github.com/Gerijacki/mcp-guard/internal/finding"
	"github.com/Gerijacki/mcp-guard/internal/rules"
	"github.com/Gerijacki/mcp-guard/internal/source"
)

// DefaultMaxFileSize skips files larger than this (bundles, generated code, data dumps).
const DefaultMaxFileSize = 1 << 20

// skipDirs are never descended into.
var skipDirs = map[string]bool{
	".git": true, ".hg": true, ".svn": true, "node_modules": true, "vendor": true,
	".venv": true, "venv": true, "__pycache__": true, ".mypy_cache": true, ".pytest_cache": true,
	".ruff_cache": true, ".tox": true, "site-packages": true, "dist": true, "build": true,
	".next": true, ".nuxt": true, ".turbo": true, ".cache": true, "coverage": true, "target": true,
	".terraform": true, ".idea": true,
}

// skipFiles are lockfiles and other generated files that only produce noise.
var skipFiles = map[string]bool{
	"package-lock.json": true, "npm-shrinkwrap.json": true, "pnpm-lock.yaml": true, "yarn.lock": true,
	"composer.lock": true, "pipfile.lock": true, "poetry.lock": true, "cargo.lock": true, "uv.lock": true,
	"bun.lock": true, "deno.lock": true,
}

// testDirs hold tests and fixtures; skipped unless Options.IncludeTests is set.
var testDirs = map[string]bool{
	"test": true, "tests": true, "__tests__": true, "testdata": true, "test_data": true,
	"fixtures": true, "__fixtures__": true, "__mocks__": true, "spec": true, "e2e": true,
}

var testFileRe = regexp.MustCompile(`(?i)(?:_test\.go|_test\.py|^test_.*\.py|^conftest\.py|\.(?:test|spec|stories)\.[cm]?[jt]sx?)$`)

func isTestFile(name string) bool { return testFileRe.MatchString(name) }

// Options configures a scan.
type Options struct {
	// Root is the file or directory to scan, as given by the user.
	Root  string
	Rules []rules.Rule
	// Ignore holds glob patterns matched against slash-separated paths relative to Root.
	Ignore            []string
	Disabled          map[string]bool
	SeverityOverrides map[string]finding.Severity
	MinSeverity       finding.Severity
	// IncludeTests scans test files and directories, which are skipped by default
	// because they are full of intentionally fake credentials and toy tools.
	IncludeTests bool
	MaxFileSize  int64
	Workers      int
	// FileTimeout bounds the analysis of a single file so that a pathological or
	// malicious input cannot hang the scan. The file is skipped with a warning.
	FileTimeout time.Duration
	// Only restricts the scan to these files (slash-separated paths as reported); used by
	// --changed-since. Nil scans everything.
	Only map[string]bool
	// PathRules disable rules for files matching a glob (config "overrides").
	PathRules []PathRule
	// MaxIndexBytes bounds the source kept in memory for cross-file analysis (default 256 MiB).
	// NoCrossFile turns the analysis of helpers defined in other files off.
	MaxIndexBytes int64
	NoCrossFile   bool
	// Inventory records the extracted tools and client-config servers in Result.Inventory.
	Inventory bool
	// RequireIgnoreReason makes inline suppressions without a justification ineffective.
	RequireIgnoreReason bool
	// WarnUnusedIgnores reports suppression comments that suppress nothing.
	WarnUnusedIgnores bool
}

// PathRule disables rules for files whose path (relative to the scan root) matches Glob.
type PathRule struct {
	Glob     string
	Disabled map[string]bool
}

// DefaultFileTimeout is the per-file analysis budget.
const DefaultFileTimeout = 10 * time.Second

// Result is the outcome of a scan.
type Result struct {
	Findings     []finding.Finding
	FilesScanned int
	ToolsFound   int
	// ResourcesFound and PromptsFound count the other MCP primitives, which are analyzed
	// like tools but reported separately.
	ResourcesFound, PromptsFound int
	ConfigsFound                 int
	// Rules are the rules that ran (after disabling).
	Rules []rules.Meta
	// Warnings describe files that could not be analyzed completely.
	Warnings []string
	// Skipped counts files that were found but not analyzed.
	Skipped SkipCounts
	// Baselined is how many findings a baseline file hid; Fixed how many baseline entries no
	// longer occur. Both are set by the caller that applies the baseline.
	Baselined, Fixed int
	// Inventory lists what was extracted from each file (only with Options.Inventory).
	Inventory []FileInventory

	inventory bool
}

// FileInventory is what the extractors found in one file.
type FileInventory struct {
	File    string
	Tools   []source.Tool
	Servers []source.ConfigServer
}

// SkipCounts says why files were not analyzed. Unreadable and timed-out files also add a
// warning; oversized and binary ones are expected and only counted.
type SkipCounts struct {
	Unreadable, TooLarge, Binary, TimedOut, Failed int
}

// Total is the number of files skipped for any reason.
func (c SkipCounts) Total() int { return c.Unreadable + c.TooLarge + c.Binary + c.TimedOut + c.Failed }

// DefaultMaxIndexBytes is the amount of source kept in memory for cross-file analysis.
// Larger trees are analyzed file by file, without following helpers across files.
const DefaultMaxIndexBytes = 256 << 20

// Scan runs the configured rules over every supported file under opts.Root.
//
// Phase 1 loads and extracts every file. Phase 2 runs the rules on each file in parallel and
// notes the calls that leave the file for helpers defined elsewhere. Phase 3 then analyzes
// those helpers, one defining file at a time, so the findings never depend on scheduling.
func Scan(opts Options) (*Result, error) {
	info, err := os.Stat(opts.Root)
	if err != nil {
		return nil, err
	}
	if opts.MaxFileSize == 0 {
		opts.MaxFileSize = DefaultMaxFileSize
	}
	if opts.MaxIndexBytes == 0 {
		opts.MaxIndexBytes = DefaultMaxIndexBytes
	}
	if opts.Workers <= 0 {
		opts.Workers = runtime.NumCPU()
	}
	if opts.FileTimeout <= 0 {
		opts.FileTimeout = DefaultFileTimeout
	}
	var active []rules.Rule
	res := &Result{inventory: opts.Inventory}
	for _, r := range opts.Rules {
		if !opts.Disabled[r.Meta().ID] {
			active = append(active, r)
			res.Rules = append(res.Rules, r.Meta())
		}
	}

	var paths []string
	var total int64
	walkErr := walk(opts.Root, info, opts, func(p string) {
		paths = append(paths, p)
		if fi, err := os.Stat(p); err == nil {
			total += fi.Size()
		}
	}, func(p string, err error) {
		res.Skipped.Unreadable++
		res.Warnings = append(res.Warnings, fmt.Sprintf("%s: cannot read: %v", filepath.ToSlash(p), err))
	})
	if walkErr != nil {
		return nil, walkErr
	}
	crossFile := !opts.NoCrossFile && len(active) > 0 && total <= opts.MaxIndexBytes
	if !opts.NoCrossFile && total > opts.MaxIndexBytes {
		res.Warnings = append(res.Warnings, fmt.Sprintf("cross-file analysis skipped: %d MiB of source exceeds the %d MiB limit", total>>20, opts.MaxIndexBytes>>20))
	}

	var mu sync.Mutex
	parallel := func(n int, work func(i int)) {
		jobs := make(chan int, opts.Workers*4)
		var wg sync.WaitGroup
		for w := 0; w < opts.Workers; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := range jobs {
					work(i)
				}
			}()
		}
		for i := 0; i < n; i++ {
			jobs <- i
		}
		close(jobs)
		wg.Wait()
	}

	// prepare loads and extracts a file; nil means it was skipped (already accounted for).
	prepare := func(p string) *source.File {
		f, skip, err := load(p, opts)
		mu.Lock()
		defer mu.Unlock()
		switch {
		case err != nil:
			res.Skipped.Unreadable++
			res.Warnings = append(res.Warnings, fmt.Sprintf("%s: unreadable: %v", filepath.ToSlash(p), err))
		case skip == skipTooLarge:
			res.Skipped.TooLarge++
		case skip == skipBinary:
			res.Skipped.Binary++
		}
		if f == nil {
			return nil
		}
		if o := extractSafe(f, opts); o.reason != "" {
			res.account(f, o)
			return nil
		}
		return f
	}

	// analyze runs the rules on f and records the outcome. resolve may be nil.
	var pending []rules.CrossCall
	analyze := func(f *source.File, resolve rules.Resolver) {
		o := runSafe(f, rulesFor(active, opts, f.Path), opts, resolve)
		mu.Lock()
		res.account(f, o)
		pending = append(pending, o.pending...)
		mu.Unlock()
	}

	if !crossFile {
		parallel(len(paths), func(i int) {
			if f := prepare(paths[i]); f != nil {
				analyze(f, nil)
			}
		})
	} else {
		var units []*source.File
		parallel(len(paths), func(i int) {
			if f := prepare(paths[i]); f != nil {
				mu.Lock()
				units = append(units, f)
				mu.Unlock()
			}
		})
		sort.Slice(units, func(i, j int) bool { return units[i].Path < units[j].Path })
		ix := buildIndex(units)
		parallel(len(units), func(i int) { analyze(units[i], ix.resolve) })
		res.checkCross(active, opts, pending, ix.resolve)
	}

	sort.Strings(res.Warnings)
	sort.Slice(res.Inventory, func(i, j int) bool { return res.Inventory[i].File < res.Inventory[j].File })
	res.Findings = postprocess(res.Findings, opts)
	return res, nil
}

// account folds the outcome of analyzing f into the result. The caller holds the lock.
func (res *Result) account(f *source.File, o outcome) {
	res.Warnings = append(res.Warnings, o.warnings...)
	switch {
	case o.timedOut:
		res.Skipped.TimedOut++
		res.Warnings = append(res.Warnings, fmt.Sprintf("%s: skipped, %s", f.Path, o.reason))
	case o.reason != "":
		res.Skipped.Failed++
		res.Warnings = append(res.Warnings, fmt.Sprintf("%s: skipped, %s", f.Path, o.reason))
	case o.analyzed:
		res.FilesScanned++
		for _, t := range f.Tools {
			switch t.Kind {
			case "resource":
				res.ResourcesFound++
			case "prompt":
				res.PromptsFound++
			default:
				res.ToolsFound++
			}
		}
		if f.IsMCPConfig {
			res.ConfigsFound++
		}
		res.Findings = append(res.Findings, o.fs...)
		if res.inventory && (len(f.Tools) > 0 || len(f.Servers) > 0) {
			res.Inventory = append(res.Inventory, FileInventory{File: f.Path, Tools: f.Tools, Servers: f.Servers})
		}
	}
}

// checkCross runs phase 3: helpers reached from other files, in rounds of increasing depth.
func (res *Result) checkCross(active []rules.Rule, opts Options, pending []rules.CrossCall, resolve rules.Resolver) {
	doneBy := map[*source.File]map[string]bool{} // per defining file: each is used by one goroutine at a time
	for round := 0; round < 3 && len(pending) > 0; round++ {
		rules.SortCalls(pending)
		groups := map[*source.File][]rules.CrossCall{}
		var order []*source.File
		for _, c := range pending {
			if _, ok := groups[c.Origin]; !ok {
				order = append(order, c.Origin)
				if doneBy[c.Origin] == nil {
					doneBy[c.Origin] = map[string]bool{}
				}
			}
			groups[c.Origin] = append(groups[c.Origin], c)
		}
		sort.Slice(order, func(i, j int) bool { return order[i].Path < order[j].Path })
		var mu sync.Mutex
		var next []rules.CrossCall
		jobs := make(chan *source.File, opts.Workers*4)
		var wg sync.WaitGroup
		for w := 0; w < opts.Workers; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for g := range jobs {
					fs, more, warn := crossSafe(g, rulesFor(active, opts, g.Path), groups[g], resolve, doneBy[g], opts)
					mu.Lock()
					res.Findings = append(res.Findings, fs...)
					next = append(next, more...)
					if warn != "" {
						res.Warnings = append(res.Warnings, warn)
					}
					mu.Unlock()
				}
			}()
		}
		for _, g := range order {
			jobs <- g
		}
		close(jobs)
		wg.Wait()
		pending = next
	}
}

// rulesFor returns the active rules minus those disabled for path by a config override.
func rulesFor(active []rules.Rule, opts Options, path string) []rules.Rule {
	if len(opts.PathRules) == 0 {
		return active
	}
	rel, err := filepath.Rel(opts.Root, path)
	if err != nil || rel == "." {
		rel = filepath.Base(path)
	}
	rel = filepath.ToSlash(rel)
	var off map[string]bool
	for _, pr := range opts.PathRules {
		if matchAny([]string{pr.Glob}, rel) {
			if off == nil {
				off = map[string]bool{}
			}
			for id := range pr.Disabled {
				off[id] = true
			}
		}
	}
	if off == nil {
		return active
	}
	out := make([]rules.Rule, 0, len(active))
	for _, r := range active {
		if !off[r.Meta().ID] {
			out = append(out, r)
		}
	}
	return out
}

type outcome struct {
	fs       []finding.Finding
	warnings []string
	pending  []rules.CrossCall
	reason   string // non-empty: the file was skipped
	timedOut bool
	analyzed bool
}

// guarded runs fn with the time budget. A panic is recovered and reported as a skipped file,
// so one bad input cannot kill the scan; on timeout the goroutine is abandoned (it only
// touches the file it was given).
func guarded(budget time.Duration, fn func() outcome) outcome {
	done := make(chan outcome, 1)
	go func() {
		defer func() {
			if p := recover(); p != nil {
				done <- outcome{reason: fmt.Sprintf("internal error: %v", p)}
			}
		}()
		done <- fn()
	}()
	timer := time.NewTimer(budget)
	defer timer.Stop()
	select {
	case o := <-done:
		return o
	case <-timer.C:
		return outcome{reason: fmt.Sprintf("analysis took longer than %s", budget), timedOut: true}
	}
}

func extractSafe(f *source.File, opts Options) outcome {
	return guarded(opts.FileTimeout, func() outcome {
		extract.Extract(f)
		return outcome{}
	})
}

// runSafe runs the rules on an extracted file. With a resolver it also records the calls into
// helpers defined in other files.
func runSafe(f *source.File, active []rules.Rule, opts Options, resolve rules.Resolver) outcome {
	return guarded(opts.FileTimeout, func() outcome {
		var pending []rules.CrossCall
		if resolve != nil {
			pending = rules.PendingCalls(f, resolve)
		}
		var out []finding.Finding
		for _, r := range active {
			out = append(out, r.Check(f)...)
		}
		fs, warnings := suppress(f, out, opts.RequireIgnoreReason, opts.WarnUnusedIgnores)
		return outcome{fs: fs, warnings: warnings, pending: pending, analyzed: true}
	})
}

// crossSafe analyzes the helpers of g reached from other files (see rules.CheckCross).
func crossSafe(g *source.File, active []rules.Rule, calls []rules.CrossCall, resolve rules.Resolver, done map[string]bool, opts Options) ([]finding.Finding, []rules.CrossCall, string) {
	var more []rules.CrossCall
	o := guarded(opts.FileTimeout, func() outcome {
		fs, next := rules.CheckCross(active, g, calls, resolve, done)
		more = next
		fs, warnings := suppress(g, fs, opts.RequireIgnoreReason, false)
		return outcome{fs: fs, warnings: warnings}
	})
	if o.reason != "" {
		return nil, nil, fmt.Sprintf("%s: helpers called from other files were not analyzed, %s", g.Path, o.reason)
	}
	return o.fs, more, ""
}

// walk calls emit for every file to scan. Entries that cannot be read are passed to
// unreadable and the walk continues; only a failure on the root itself is returned.
func walk(root string, info fs.FileInfo, opts Options, emit func(string), unreadable func(string, error)) error {
	send := func(p string) {
		if opts.Only != nil {
			abs, err := filepath.Abs(p)
			if err != nil || !opts.Only[filepath.ToSlash(abs)] {
				return
			}
		}
		emit(p)
	}
	if !info.IsDir() {
		send(root)
		return nil
	}
	return filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if p == root {
				return err
			}
			unreadable(p, err)
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if p != root && (skipDirs[d.Name()] || matchAny(opts.Ignore, rel) || (!opts.IncludeTests && testDirs[strings.ToLower(d.Name())])) {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() || skipFiles[strings.ToLower(d.Name())] || matchAny(opts.Ignore, rel) {
			return nil
		}
		if !opts.IncludeTests && isTestFile(d.Name()) {
			return nil
		}
		if source.DetectLanguage(p) == source.Unknown {
			return nil
		}
		send(p)
		return nil
	})
}

type skipKind int

const (
	skipNone skipKind = iota
	skipTooLarge
	skipBinary
)

func load(p string, opts Options) (*source.File, skipKind, error) {
	info, err := os.Stat(p)
	if err != nil {
		return nil, skipNone, err
	}
	if info.Size() > opts.MaxFileSize {
		return nil, skipTooLarge, nil
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, skipNone, err
	}
	if bytes.IndexByte(b[:min(len(b), 8000)], 0) >= 0 {
		return nil, skipBinary, nil
	}
	return source.NewFile(filepath.ToSlash(filepath.Clean(p)), source.DetectLanguage(p), string(b)), skipNone, nil
}

// postprocess applies severity overrides and the minimum severity, removes duplicates,
// computes fingerprints and sorts. Identical findings on identical lines of one file get
// distinct fingerprints (an occurrence index), so a baseline can tell them apart.
func postprocess(fs []finding.Finding, opts Options) []finding.Finding {
	seen := map[string]bool{}
	out := make([]finding.Finding, 0, len(fs))
	for _, fd := range fs {
		if sev, ok := opts.SeverityOverrides[fd.RuleID]; ok {
			fd.Severity = sev
		}
		if fd.Severity < opts.MinSeverity {
			continue
		}
		key := fmt.Sprintf("%s|%s|%d|%s", fd.RuleID, fd.File, fd.Line, fd.Message)
		if seen[key] {
			continue
		}
		seen[key] = true
		fd.ComputeFingerprint()
		out = append(out, fd)
	}
	finding.Sort(out)
	finding.NumberDuplicates(out)
	return out
}
