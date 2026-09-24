package main

import (
	"context"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func main() {
	s := server.NewMCPServer("notes", "1.0.0")
	s.AddTool(mcp.NewTool("search_notes",
		mcp.WithDescription("Full-text search over the user's notes."),
		mcp.WithString("query", mcp.Required(), mcp.Description("Search terms")),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return mcp.NewToolResultText("no results"), nil
	})
}
