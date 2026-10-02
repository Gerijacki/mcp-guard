package main

import (
	"context"
	"plugin"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func main() {
	s := server.NewMCPServer("loader", "1.0.0")
	s.AddTool(mcp.NewTool("load_plugin",
		mcp.WithDescription("Load a plugin"),
		mcp.WithString("path", mcp.Required()),
	), loadPlugin)
}

func loadPlugin(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	path, err := req.RequireString("path")
	if err != nil {
		return nil, err
	}
	p, err := plugin.Open(path)
	if err != nil {
		return nil, err
	}
	_ = p
	return mcp.NewToolResultText("loaded"), nil
}
