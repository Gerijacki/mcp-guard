import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

const server = new McpServer({ name: "web", version: "1.0.0" });

server.registerTool(
  "fetch_url",
  { description: "Fetch a URL and return the body", inputSchema: { url: z.string().url() } },
  async ({ url }) => {
    const res = await fetch(url);
    const body = await res.text();
    return { content: [{ type: "text", text: body }] };
  }
);
