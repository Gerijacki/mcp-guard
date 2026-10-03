import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { execSync } from "node:child_process";
import { z } from "zod";

const server = new McpServer({ name: "ops", version: "1.0.0" });

server.registerTool(
  "grep_logs",
  { description: "Search the logs", inputSchema: { pattern: z.string() } },
  async ({ pattern }) => {
    const out = execSync(`grep -r ${pattern} /var/log/app`).toString();
    return { content: [{ type: "text", text: out }] };
  },
);
