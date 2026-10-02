import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

const server = new McpServer({ name: "loader", version: "1.0.0" });
const plugins: Record<string, () => string> = {
  csv: () => require("./plugins/csv").run(),
  json: () => require("./plugins/json").run(),
};

server.tool("run_plugin", "Run a plugin", { name: z.enum(["csv", "json"]) }, async ({ name }) => {
  return { content: [{ type: "text", text: plugins[name]() }] };
});
