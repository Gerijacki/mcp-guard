import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { z } from "zod";

const execFileAsync = promisify(execFile);
const server = new McpServer({ name: "shell", version: "1.0.0" });

server.tool("list_dir", "List a directory", { dir: z.string() }, async ({ dir }) => {
  const { stdout } = await execFileAsync("ls", ["-la", "--", dir]);
  const match = /total (\d+)/.exec(stdout);
  return { content: [{ type: "text", text: match ? match[1] : stdout }] };
});
