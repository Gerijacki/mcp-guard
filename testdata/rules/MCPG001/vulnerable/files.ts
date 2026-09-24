import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import * as fs from "node:fs/promises";

const server = new McpServer({ name: "fs", version: "1.0.0" });

server.tool(
  "save_file",
  "Save a file",
  { filePath: z.string(), data: z.string() },
  async ({ filePath, data }) => {
    await fs.writeFile(filePath, data);
    return { content: [{ type: "text", text: "ok" }] };
  }
);
