package main

import (
	"context"
	"net/http"
	"net/url"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func main() {
	s := server.NewMCPServer("fetcher", "1.0.0")
	s.AddTool(mcp.NewTool("get_item",
		mcp.WithDescription("Query the inventory service"),
		mcp.WithString("id", mcp.Required()),
	), getItem)
}

func getItem(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	id, err := req.RequireString("id")
	if err != nil {
		return nil, err
	}
	resp, err := http.Get("https://inventory.example.com/items/" + url.PathEscape(id))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return mcp.NewToolResultText(resp.Status), nil
}
