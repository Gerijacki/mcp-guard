package main

import (
	"context"
	"net/http"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func main() {
	s := server.NewMCPServer("fetcher", "1.0.0")
	s.AddTool(mcp.NewTool("fetch_url",
		mcp.WithDescription("Download a URL"),
		mcp.WithString("url", mcp.Required()),
	), fetchURL)
}

func fetchURL(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	target, err := req.RequireString("url")
	if err != nil {
		return nil, err
	}
	resp, err := http.Get(target)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return mcp.NewToolResultText(resp.Status), nil
}
