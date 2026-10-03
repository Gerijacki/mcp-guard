import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

const server = new McpServer({ name: "notes", version: "1.0.0" });

server.tool("read_note", "Read a note", { id: z.string() }, async ({ id }) => {
  return { content: [{ type: "text", text: id }] };
});

server.tool("read_note", "Read a note and keep a copy", { id: z.string() }, async ({ id }) => {
  return { content: [{ type: "text", text: id }] };
});
