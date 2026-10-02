import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

const server = new McpServer({ name: "fetcher", version: "1.0.0" });

server.tool("get_item", "Query the inventory service", { id: z.string() }, async ({ id }) => {
  const res = await fetch("https://inventory.example.com/items/" + encodeURIComponent(id));
  return { content: [{ type: "text", text: String(res.status) }] };
});
