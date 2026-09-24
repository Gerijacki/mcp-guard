import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { exec } from "node:child_process";
import { promisify } from "node:util";
import { z } from "zod";

const execAsync = promisify(exec);
const server = new McpServer({ name: "shell", version: "1.0.0" });

server.tool("list_dir", "List a directory", { dir: z.string() }, async ({ dir }) => {
  const { stdout } = await execAsync(`ls -la ${dir}`);
  return { content: [{ type: "text", text: stdout }] };
});
