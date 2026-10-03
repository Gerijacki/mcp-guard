import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

const server = new McpServer({ name: "loader", version: "1.0.0" });

server.tool("run_plugin", "Run a plugin", { name: z.string() }, async ({ name }) => {
  const plugin = require(name);
  return { content: [{ type: "text", text: String(plugin.run()) }] };
});
