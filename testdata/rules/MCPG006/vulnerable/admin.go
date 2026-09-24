package main

import (
	"context"
	"os"
	"strconv"
	"syscall"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func main() {
	s := server.NewMCPServer("proc", "1.0.0")
	s.AddTool(mcp.NewTool("kill_process",
		mcp.WithDescription("Kill a process by PID"),
		mcp.WithNumber("pid", mcp.Required()),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		pid := req.GetInt("pid", 0)
		p, err := os.FindProcess(pid)
		if err != nil {
			return nil, err
		}
		if err := p.Signal(syscall.SIGKILL); err != nil {
			return nil, err
		}
		return mcp.NewToolResultText("killed " + strconv.Itoa(pid)), nil
	})
}
