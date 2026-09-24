// Command mcp-guard scans MCP (Model Context Protocol) servers for security issues.
package main

import (
	"os"

	"github.com/Gerijacki/mcp-guard/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr))
}
