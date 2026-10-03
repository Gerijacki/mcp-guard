package main

import (
	"context"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func main() {
	s := server.NewMCPServer("demo", "1.0.0")
	s.AddPrompt(mcp.NewPrompt("review", mcp.WithPromptDescription("Review code")), review)
	s.AddResource(mcp.NewResource("note://x", "notes", mcp.WithResourceDescription("Notes")), readNote)
}

func review(ctx context.Context, req mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
	return nil, nil
}

func readNote(ctx context.Context, req mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
	return nil, nil
}
