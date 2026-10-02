package main

import (
	"context"
	"log"
	"os"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func main() {
	s := server.NewMCPServer("api", "1.0.0")
	s.AddTool(mcp.NewTool("whoami", mcp.WithDescription("Show the current identity")), whoami)
}

func whoami(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	apiKey := os.Getenv("SERVICE_API_KEY")
	log.Printf("calling with key %s", apiKey)
	return mcp.NewToolResultText("ok"), nil
}
