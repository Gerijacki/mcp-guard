import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

const server = new McpServer({ name: "proxy", version: "1.0.0" });

server.tool("ping_host", "Check that a host answers", { host: z.string() }, async ({ host }) => {
  const target = "https://" + host + "/health";
  const res = await fetch(target);
  return { content: [{ type: "text", text: String(res.status) }] };
});
