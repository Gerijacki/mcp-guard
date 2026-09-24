import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import * as fs from "node:fs/promises";
import * as path from "node:path";

const ROOT = path.resolve("./workspace");
const server = new McpServer({ name: "fs", version: "1.0.0" });

server.tool(
  "save_file",
  "Save a file inside the workspace",
  { filePath: z.string(), data: z.string() },
  async ({ filePath, data }) => {
    const target = path.resolve(ROOT, filePath);
    const rel = path.relative(ROOT, target);
    if (rel.startsWith("..") || path.isAbsolute(rel)) {
      throw new Error("path escapes the workspace");
    }
    await fs.writeFile(target, data);
    return { content: [{ type: "text", text: "ok" }] };
  }
);
