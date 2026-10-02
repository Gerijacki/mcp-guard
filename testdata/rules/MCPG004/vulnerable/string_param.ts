import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { execSync } from "node:child_process";
import { z } from "zod";

const server = new McpServer({ name: "ops", version: "1.0.0" });

server.tool("report", "Show a system report", { kind: z.string(), lines: z.number().int() }, async ({ kind, lines }) => {
  const out = execSync(`report-${kind} --lines ${lines}`).toString();
  return { content: [{ type: "text", text: out }] };
});
