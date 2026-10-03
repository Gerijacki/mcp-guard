package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/Gerijacki/mcp-guard/internal/lock"
	"github.com/Gerijacki/mcp-guard/internal/scanner"
)

// runLock writes mcp-guard.lock: a fingerprint of every tool description, parameter list and
// server launch command, to be committed and checked by `scan --lock` (rule MCPG016).
func runLock(args []string, stdout, stderr io.Writer) int {
	var out string
	var ignore listFlag
	var includeTests bool
	fs := flag.NewFlagSet("lock", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&out, "output", "", "lock file to write (default: mcp-guard.lock in the scanned directory)")
	fs.StringVar(&out, "o", "", "shorthand for --output")
	fs.Var(&ignore, "ignore", "glob of paths to skip (repeatable)")
	fs.BoolVar(&includeTests, "include-tests", false, "also include test files and directories")
	pos, err := parseInterleaved(fs, args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitOK
		}
		return ExitError
	}
	if len(pos) > 1 {
		fmt.Fprintln(stderr, "usage: mcp-guard lock [path] [-o file]")
		return ExitError
	}
	root := "."
	if len(pos) == 1 {
		root = pos[0]
	}
	info, err := os.Stat(root)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return ExitError
	}
	if out == "" {
		dir := root
		if !info.IsDir() {
			dir = filepath.Dir(root)
		}
		out = filepath.Join(dir, lock.DefaultName)
	}
	res, err := scanner.Scan(scanner.Options{Root: root, Ignore: ignore, IncludeTests: includeTests, Inventory: true})
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return ExitError
	}
	var files []lock.Source
	for _, inv := range res.Inventory {
		files = append(files, lock.Source{Path: inv.File, Tools: inv.Tools, Servers: inv.Servers})
	}
	l := lock.Build(root, files)
	if err := l.Save(out); err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return ExitError
	}
	fmt.Fprintf(stdout, "wrote %s: %d tools/resources/prompts and %d servers\n", out, len(l.Tools), len(l.Servers))
	return ExitOK
}
