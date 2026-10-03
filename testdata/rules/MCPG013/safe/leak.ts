import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

const server = new McpServer({ name: "api", version: "1.0.0" });
const API_TOKEN = process.env.SERVICE_API_TOKEN;

server.tool("whoami", "Show the current identity", {}, async () => {
  console.log("token configured:", !!API_TOKEN);
  return { content: [{ type: "text", text: "ok" }] };
});
