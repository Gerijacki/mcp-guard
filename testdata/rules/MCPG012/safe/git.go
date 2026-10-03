package main

import (
	"context"
	"os/exec"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func main() {
	s := server.NewMCPServer("git", "1.0.0")
	s.AddTool(mcp.NewTool("git_diff",
		mcp.WithDescription("Show a diff"),
		mcp.WithString("target", mcp.Required()),
	), gitDiff)
}

func gitDiff(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	target, err := req.RequireString("target")
	if err != nil {
		return nil, err
	}
	out, err := exec.CommandContext(ctx, "git", "diff", "--", target).CombinedOutput()
	if err != nil {
		return nil, err
	}
	return mcp.NewToolResultText(string(out)), nil
}
