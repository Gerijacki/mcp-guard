package main

import (
	"context"
	"encoding/json"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func main() {
	s := server.NewMCPServer("loader", "1.0.0")
	s.AddTool(mcp.NewTool("load_state",
		mcp.WithDescription("Restore state (JSON)"),
		mcp.WithString("data", mcp.Required()),
	), loadState)
}

func loadState(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	data, err := req.RequireString("data")
	if err != nil {
		return nil, err
	}
	var v map[string]any
	if err := json.Unmarshal([]byte(data), &v); err != nil {
		return nil, err
	}
	return mcp.NewToolResultText("ok"), nil
}
