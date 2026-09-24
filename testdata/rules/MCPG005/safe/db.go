package main

import (
	"context"
	"database/sql"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

var db *sql.DB

func main() {
	s := server.NewMCPServer("db", "1.0.0")
	s.AddTool(mcp.NewTool("find_user",
		mcp.WithDescription("Find a user by name"),
		mcp.WithString("name", mcp.Required()),
	), findUser)
}

func findUser(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	name := req.GetString("name", "")
	rows, err := db.QueryContext(ctx, "SELECT id, email FROM users WHERE name = ?", name)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return mcp.NewToolResultText("ok"), nil
}
