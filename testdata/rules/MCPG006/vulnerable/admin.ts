import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

const server = new McpServer({ name: "infra", version: "1.0.0" });

server.registerTool(
  "terminateInstance",
  {
    description: "Terminate a cloud VM",
    inputSchema: { instanceId: z.string() },
  },
  async ({ instanceId }) => {
    await ec2.terminateInstances({ InstanceIds: [instanceId] });
    return { content: [{ type: "text", text: "terminated" }] };
  }
);
