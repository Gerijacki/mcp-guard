package main

import (
	"context"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func main() {
	s := server.NewMCPServer("clock", "1.0.0")
	s.AddTool(mcp.NewTool("now",
		mcp.WithDescription("Return the current UTC time"),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return mcp.NewToolResultText(time.Now().UTC().Format(time.RFC3339)), nil
	})
}
