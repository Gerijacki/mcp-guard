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

var testFileRe = regexp.MustCompile(`(?i)(?:_test\.go|_test\.py|^test_.*\.py|^conftest\.py|\.(?:test|spec)\.[cm]?[jt]sx?)$`)

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
}

// DefaultFileTimeout is the per-file analysis budget.
const DefaultFileTimeout = 10 * time.Second

// Result is the outcome of a scan.
type Result struct {
	Findings     []finding.Finding
	FilesScanned int
	ToolsFound   int
	ConfigsFound int
	// Rules are the rules that ran (after disabling).
	Rules []rules.Meta
	// Warnings describe files that could not be analyzed completely.
	Warnings []string
}

// Scan runs the configured rules over every supported file under opts.Root.
func Scan(opts Options) (*Result, error) {
	info, err := os.Stat(opts.Root)
	if err != nil {
		return nil, err
	}
	if opts.MaxFileSize == 0 {
		opts.MaxFileSize = DefaultMaxFileSize
	}
	if opts.Workers <= 0 {
		opts.Workers = runtime.NumCPU()
	}
	if opts.FileTimeout <= 0 {
		opts.FileTimeout = DefaultFileTimeout
	}
	var active []rules.Rule
	res := &Result{}
	for _, r := range opts.Rules {
		if !opts.Disabled[r.Meta().ID] {
			active = append(active, r)
			res.Rules = append(res.Rules, r.Meta())
		}
	}

	paths, err := collect(opts.Root, info, opts)
	if err != nil {
		return nil, err
	}

	var (
		mu   sync.Mutex
		wg   sync.WaitGroup
		jobs = make(chan string)
	)
	for w := 0; w < opts.Workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range jobs {
				f, err := load(p, opts)
				if err != nil || f == nil {
					continue // unreadable or binary: skip silently
				}
				fs, ok := analyze(f, active, opts.FileTimeout)
				mu.Lock()
				if !ok {
					res.Warnings = append(res.Warnings, fmt.Sprintf("%s: skipped, analysis took longer than %s", f.Path, opts.FileTimeout))
					mu.Unlock()
					continue
				}
				res.FilesScanned++
				res.ToolsFound += len(f.Tools)
				if f.IsMCPConfig {
					res.ConfigsFound++
				}
				res.Findings = append(res.Findings, fs...)
				mu.Unlock()
			}
		}()
	}
	for _, p := range paths {
		jobs <- p
	}
	close(jobs)
	wg.Wait()

	res.Findings = postprocess(res.Findings, opts)
	return res, nil
}

// analyze extracts tools and runs the rules on f within the time budget. On timeout the
// worker goroutine is abandoned (it only touches f) and ok is false.
func analyze(f *source.File, active []rules.Rule, budget time.Duration) (fs []finding.Finding, ok bool) {
	done := make(chan []finding.Finding, 1)
	go func() {
		extract.Extract(f)
		var out []finding.Finding
		for _, r := range active {
			out = append(out, r.Check(f)...)
		}
		done <- suppress(f, out)
	}()
	timer := time.NewTimer(budget)
	defer timer.Stop()
	select {
	case fs = <-done:
		return fs, true
	case <-timer.C:
		return nil, false
	}
}

// collect returns the files to scan.
func collect(root string, info fs.FileInfo, opts Options) ([]string, error) {
	if !info.IsDir() {
		return []string{root}, nil
	}
	var out []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if p == root {
				return err
			}
			return nil // unreadable entry: keep going
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
		out = append(out, p)
		return nil
	})
	return out, err
}

func load(p string, opts Options) (*source.File, error) {
	info, err := os.Stat(p)
	if err != nil {
		return nil, err
	}
	if info.Size() > opts.MaxFileSize {
		return nil, nil
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	if bytes.IndexByte(b[:min(len(b), 8000)], 0) >= 0 {
		return nil, nil // binary
	}
	return source.NewFile(filepath.ToSlash(filepath.Clean(p)), source.DetectLanguage(p), string(b)), nil
}

// ignoreRe matches inline suppressions: "mcp-guard:ignore" optionally followed by rule IDs.
var ignoreRe = regexp.MustCompile(`mcp-guard:ignore\b([^\n]*)`)
var ruleIDRe = regexp.MustCompile(`\b[A-Z][A-Z0-9_-]{2,31}\b`)

// suppress drops findings whose line, or the line above, carries an ignore comment.
func suppress(f *source.File, fs []finding.Finding) []finding.Finding {
	if !strings.Contains(f.Content, "mcp-guard:ignore") {
		return fs
	}
	out := fs[:0]
	for _, fd := range fs {
		if !suppressedAt(f.Line(fd.Line), fd.RuleID) && !suppressedAt(f.Line(fd.Line-1), fd.RuleID) {
			out = append(out, fd)
		}
	}
	return out
}

func suppressedAt(line, ruleID string) bool {
	m := ignoreRe.FindStringSubmatch(line)
	if m == nil {
		return false
	}
	ids := ruleIDRe.FindAllString(m[1], -1)
	if len(ids) == 0 {
		return true
	}
	for _, id := range ids {
		if id == ruleID {
			return true
		}
	}
	return false
}

// postprocess applies severity overrides and the minimum severity, removes duplicates,
// computes fingerprints and sorts.
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
	return out
}
