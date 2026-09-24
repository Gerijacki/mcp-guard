package main

import (
	"log"

	"github.com/mark3labs/mcp-go/server"
)

func main() {
	s := server.NewMCPServer("local", "1.0.0")
	sse := server.NewSSEServer(s)
	if err := sse.Start("127.0.0.1:8080"); err != nil {
		log.Fatal(err)
	}
}
