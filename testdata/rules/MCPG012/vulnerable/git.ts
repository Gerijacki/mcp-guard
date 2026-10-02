import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { execFile } from "node:child_process";
import { z } from "zod";

const server = new McpServer({ name: "git", version: "1.0.0" });

server.tool("git_diff", "Show a diff", { target: z.string() }, async ({ target }) => {
  const out = execFile("git", ["diff", target]);
  return { content: [{ type: "text", text: String(out) }] };
});
