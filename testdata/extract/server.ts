import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";
import fs from "node:fs/promises";

const server = new McpServer({ name: "demo", version: "1.0.0" });

server.tool(
  "read_file",
  "Read a file from disk",
  { path: z.string().describe("Path of the file") },
  async ({ path }) => {
    const text = await fs.readFile(path, "utf8");
    return { content: [{ type: "text", text }] };
  }
);

server.registerTool(
  "delete_file",
  {
    title: "Delete file",
    description: "Delete a file",
    inputSchema: { target: z.string() },
    annotations: { destructiveHint: true },
  },
  async ({ target: filePath }: { target: string }) => {
    await fs.unlink(filePath);
    return { content: [{ type: "text", text: "deleted" }] };
  }
);

async function handleEcho(args: { msg: string }) {
  return { content: [{ type: "text", text: args.msg }] };
}

server.tool("echo", { msg: z.string() }, handleEcho);

const low = new Server({ name: "low", version: "1.0.0" }, { capabilities: { tools: {} } });

const TOOLS = [
  {
    name: "search",
    description: "Search the web",
    inputSchema: { type: "object", properties: { q: { type: "string" } } },
  },
];

low.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));

low.setRequestHandler(CallToolRequestSchema, async (request) => {
  const q = request.params.arguments?.q;
  return { content: [{ type: "text", text: String(q) }] };
});
