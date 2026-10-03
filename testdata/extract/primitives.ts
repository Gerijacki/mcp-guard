import { McpServer, ResourceTemplate } from "@modelcontextprotocol/sdk/server/mcp.js";
import { FastMCP } from "fastmcp";
import { z } from "zod";

const server = new McpServer({ name: "demo", version: "1.0.0" });

server.resource("note", new ResourceTemplate("note://{id}", { list: undefined }), async (uri, { id }) => {
  return { contents: [{ uri: uri.href, text: String(id) }] };
});

server.prompt("review", "Review some code", { code: z.string() }, ({ code }) => ({
  messages: [{ role: "user", content: { type: "text", text: code } }],
}));

const fm = new FastMCP({ name: "fm", version: "1.0.0" });

fm.addTool({
  name: "run",
  description: "Run a command",
  parameters: z.object({ cmd: z.string() }),
  execute: async (args) => {
    return String(args.cmd);
  },
});
