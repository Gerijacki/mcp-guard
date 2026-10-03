import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

const server = new McpServer({ name: "fetcher", version: "1.0.0" });

server.tool("fetch_url", "Download a URL", { url: z.string() }, async ({ url }) => {
  const res = await fetch(url);
  return { content: [{ type: "text", text: String(res.status) }] };
});
