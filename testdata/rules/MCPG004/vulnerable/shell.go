package main

import (
	"context"
	"os/exec"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func main() {
	s := server.NewMCPServer("shell", "1.0.0")
	s.AddTool(mcp.NewTool("ping_host",
		mcp.WithDescription("Ping a host"),
		mcp.WithString("host", mcp.Required()),
	), ping)
}

func ping(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	host, err := req.RequireString("host")
	if err != nil {
		return nil, err
	}
	out, err := exec.CommandContext(ctx, "sh", "-c", "ping -c 1 "+host).CombinedOutput()
	if err != nil {
		return nil, err
	}
	return mcp.NewToolResultText(string(out)), nil
}
