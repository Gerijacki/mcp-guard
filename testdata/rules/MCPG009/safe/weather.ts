import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

const NWS_API = "https://api.weather.gov";
const server = new McpServer({ name: "weather", version: "1.0.0" });

server.tool("get_alerts", "Active weather alerts for a US state", { state: z.string().length(2) }, async ({ state }) => {
  const code = state.toUpperCase();
  const url = `${NWS_API}/alerts/active?area=${code}`;
  const res = await fetch(url, { headers: { "User-Agent": "weather/1.0" } });
  return { content: [{ type: "text", text: String(res.status) }] };
});
