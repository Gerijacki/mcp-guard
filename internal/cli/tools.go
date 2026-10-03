package cli

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/Gerijacki/mcp-guard/internal/scanner"
	"github.com/Gerijacki/mcp-guard/internal/source"
)

// runTools prints what the extractors found: the first thing to check when a finding is
// missing is whether the tool was recognized at all.
func runTools(args []string, stdout, stderr io.Writer) int {
	var format string
	var ignore listFlag
	var includeTests bool
	fs := flag.NewFlagSet("tools", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&format, "format", "text", "output format: text or json")
	fs.StringVar(&format, "f", "text", "shorthand for --format")
	fs.Var(&ignore, "ignore", "glob of paths to skip (repeatable)")
	fs.BoolVar(&includeTests, "include-tests", false, "also scan test files and directories")
	pos, err := parseInterleaved(fs, args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitOK
		}
		return ExitError
	}
	if len(pos) > 1 || (format != "text" && format != "json") {
		fmt.Fprintln(stderr, "usage: mcp-guard tools [path] [--format text|json]")
		return ExitError
	}
	root := "."
	if len(pos) == 1 {
		root = pos[0]
	}
	if _, err := os.Stat(root); err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return ExitError
	}
	res, err := scanner.Scan(scanner.Options{Root: root, Ignore: ignore, IncludeTests: includeTests, Inventory: true})
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return ExitError
	}
	for _, w := range res.Warnings {
		fmt.Fprintln(stderr, "warning:", w)
	}
	if format == "json" {
		type toolJSON struct {
			Name        string            `json:"name"`
			Line        int               `json:"line"`
			Params      []string          `json:"params"`
			Annotations map[string]string `json:"annotations,omitempty"`
			Description string            `json:"description,omitempty"`
			BodyLines   [2]int            `json:"body_lines,omitempty"`
			Dispatcher  bool              `json:"dispatcher,omitempty"`
		}
		type fileJSON struct {
			File    string                `json:"file"`
			Tools   []toolJSON            `json:"tools"`
			Servers []source.ConfigServer `json:"servers,omitempty"`
		}
		out := []fileJSON{}
		for _, inv := range res.Inventory {
			fj := fileJSON{File: inv.File, Tools: []toolJSON{}, Servers: inv.Servers}
			for _, t := range inv.Tools {
				fj.Tools = append(fj.Tools, toolJSON{Name: t.Name, Line: t.Line, Params: nonNil(t.Params), Annotations: t.Annotations,
					Description: t.Description, BodyLines: [2]int{t.BodyStart, t.BodyEnd}, Dispatcher: t.Dispatcher})
			}
			out = append(out, fj)
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(out); err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return ExitError
		}
		return ExitOK
	}
	tools, servers := 0, 0
	for _, inv := range res.Inventory {
		fmt.Fprintln(stdout, inv.File)
		for _, t := range inv.Tools {
			tools++
			body := "metadata only (no handler body found)"
			if t.HasBody() {
				body = fmt.Sprintf("handler lines %d-%d", t.BodyStart, t.BodyEnd)
			}
			if t.Dispatcher {
				body += ", dispatcher for many tools"
			}
			fmt.Fprintf(stdout, "  tool %q (line %d): params [%s], %s\n", t.Name, t.Line, strings.Join(t.Params, ", "), body)
			if len(t.Annotations) > 0 {
				fmt.Fprintf(stdout, "    annotations: %v\n", t.Annotations)
			}
			if t.Description != "" {
				fmt.Fprintf(stdout, "    description: %s\n", oneLine(t.Description, 100))
			}
		}
		for _, s := range inv.Servers {
			servers++
			fmt.Fprintf(stdout, "  server %q (line %d): %s %s%s\n", s.Name, s.Line, s.Command, strings.Join(s.Args, " "), s.URL)
		}
	}
	fmt.Fprintf(stdout, "\n%d tools and %d client-config servers in %d files\n", tools, servers, res.FilesScanned)
	return ExitOK
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func oneLine(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len([]rune(s)) > n {
		s = string([]rune(s)[:n]) + "…"
	}
	return s
}
