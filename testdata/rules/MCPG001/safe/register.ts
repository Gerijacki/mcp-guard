import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { readFileSync } from "node:fs";
import path from "node:path";
import { z } from "zod";

const server = new McpServer({ name: "files", version: "1.0.0" });
const ROOT = path.resolve("/srv/files");

server.registerTool(
  "read_file",
  { description: "Read a file", inputSchema: { name: z.string() } },
  async ({ name }) => {
    const target = path.resolve(ROOT, name);
    const rel = path.relative(ROOT, target);
    if (rel.startsWith("..") || path.isAbsolute(rel)) throw new Error("outside root");
    return { content: [{ type: "text", text: readFileSync(target, "utf8") }] };
  },
);
