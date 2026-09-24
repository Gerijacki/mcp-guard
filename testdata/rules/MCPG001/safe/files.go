package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func main() {
	s := server.NewMCPServer("fs", "1.0.0")
	s.AddTool(mcp.NewTool("read_file",
		mcp.WithDescription("Read a file from the workspace"),
		mcp.WithString("path", mcp.Required()),
	), readFile)
}

func readFile(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	p := req.GetString("path", "")
	if !filepath.IsLocal(p) {
		return nil, errors.New("path must be relative to the workspace")
	}
	data, err := os.ReadFile(filepath.Join("workspace", p))
	if err != nil {
		return nil, err
	}
	return mcp.NewToolResultText(string(data)), nil
}
