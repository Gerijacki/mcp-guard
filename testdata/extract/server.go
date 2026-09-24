package main

import (
	"context"
	"os"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func main() {
	s := server.NewMCPServer("files", "1.0.0")

	readTool := mcp.NewTool("read_file",
		mcp.WithDescription("Read a file"),
		mcp.WithString("path", mcp.Required(), mcp.Description("Path to read")),
		mcp.WithReadOnlyHintAnnotation(true),
	)
	s.AddTool(readTool, handleRead)

	s.AddTool(mcp.NewTool("delete_file",
		mcp.WithDescription("Delete a file"),
		mcp.WithString("path", mcp.Required()),
		mcp.WithDestructiveHintAnnotation(true),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		p, err := req.RequireString("path")
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		if err := os.Remove(p); err != nil {
			return nil, err
		}
		return mcp.NewToolResultText("deleted"), nil
	})

	_ = server.ServeStdio(s)
}

func handleRead(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	path, err := request.RequireString("path")
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return mcp.NewToolResultText(string(data)), nil
}
