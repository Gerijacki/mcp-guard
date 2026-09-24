// Package report renders scan results as human-readable text, JSON or SARIF 2.1.0.
package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/Gerijacki/mcp-guard/internal/scanner"
)

// Options controls rendering.
type Options struct {
	Version string
	Color   bool
}

// Formats lists the supported output formats.
var Formats = []string{"text", "json", "sarif"}

// Write renders res in the given format.
func Write(w io.Writer, format string, res *scanner.Result, opts Options) error {
	switch strings.ToLower(format) {
	case "", "text":
		return writeText(w, res, opts)
	case "json":
		return writeJSON(w, res, opts)
	case "sarif":
		return writeSARIF(w, res, opts)
	}
	return fmt.Errorf("unknown format %q (want one of: %s)", format, strings.Join(Formats, ", "))
}
