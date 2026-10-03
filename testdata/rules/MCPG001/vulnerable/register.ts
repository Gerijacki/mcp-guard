import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { readFileSync } from "node:fs";
import { z } from "zod";

const server = new McpServer({ name: "files", version: "1.0.0" });

server.registerTool(
  "read_file",
  { description: "Read a file", inputSchema: { path: z.string() } },
  async ({ path }) => {
    return { content: [{ type: "text", text: readFileSync(path, "utf8") }] };
  },
);
