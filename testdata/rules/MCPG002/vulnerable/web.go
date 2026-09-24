package main

import (
	"context"
	"io"
	"net/http"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func main() {
	s := server.NewMCPServer("web", "1.0.0")
	s.AddTool(mcp.NewTool("get_issue",
		mcp.WithDescription("Fetch an issue from the tracker API"),
		mcp.WithString("id", mcp.Required()),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		id := req.GetString("id", "")
		resp, err := http.Get("https://tracker.example.com/api/issues/" + id)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return mcp.NewToolResultText(string(body)), nil
	})
}
