import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { sanitizeExternalContent } from "./sanitize.js";

const server = new McpServer({ name: "web", version: "1.0.0" });

server.registerTool(
  "fetch_url",
  { description: "Fetch a URL and return sanitized text", inputSchema: { url: z.string().url() } },
  async ({ url }) => {
    const res = await fetch(url);
    const body = sanitizeExternalContent(await res.text());
    return { content: [{ type: "text", text: body }] };
  }
);
