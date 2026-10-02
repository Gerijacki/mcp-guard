package main

import (
	"context"
	"fmt"
	"os/exec"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func main() {
	s := server.NewMCPServer("ops", "1.0.0")
	s.AddTool(mcp.NewTool("tail_log",
		mcp.WithDescription("Show the last lines of the application log"),
		mcp.WithNumber("lines", mcp.Required()),
	), tailLog)
}

func tailLog(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	lines, err := req.RequireInt("lines")
	if err != nil {
		return nil, err
	}
	out, err := exec.CommandContext(ctx, "sh", "-c", fmt.Sprintf("tail -n %d /var/log/app.log", lines)).CombinedOutput()
	if err != nil {
		return nil, err
	}
	return mcp.NewToolResultText(string(out)), nil
}
