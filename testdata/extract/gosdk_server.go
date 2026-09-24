package main

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type GreetArgs struct {
	Name string `json:"name" jsonschema:"who to greet"`
}

func Greet(ctx context.Context, req *mcp.CallToolRequest, args GreetArgs) (*mcp.CallToolResult, any, error) {
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "Hi " + args.Name}}}, nil, nil
}

func main() {
	server := mcp.NewServer(&mcp.Implementation{Name: "greeter"}, nil)
	mcp.AddTool(server, &mcp.Tool{Name: "greet", Description: "Say hi"}, Greet)
}
