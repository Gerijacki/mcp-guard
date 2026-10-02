import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { execSync } from "node:child_process";
import { z } from "zod";

const server = new McpServer({ name: "ops", version: "1.0.0" });

function run(command: string): string {
  return execSync(command).toString();
}

server.tool("disk_usage", "Show disk usage", { dir: z.string() }, async ({ dir }) => {
  return { content: [{ type: "text", text: run("du -sh " + dir) }] };
});
