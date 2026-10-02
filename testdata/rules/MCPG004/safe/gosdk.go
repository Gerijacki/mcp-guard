package main

import (
	"context"
	"os/exec"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type RunArgs struct {
	Host string `json:"host"`
}

func run(ctx context.Context, req *mcp.CallToolRequest, args RunArgs) (*mcp.CallToolResult, any, error) {
	out, err := exec.Command("ping", "-c", "1", "--", args.Host).CombinedOutput()
	if err != nil {
		return nil, nil, err
	}
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(out)}}}, nil, nil
}

func main() {
	server := mcp.NewServer(&mcp.Implementation{Name: "ops", Version: "1.0.0"}, nil)
	mcp.AddTool(server, &mcp.Tool{Name: "ping", Description: "Ping a host"}, run)
}
