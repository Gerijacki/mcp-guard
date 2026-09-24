import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

const ALLOWED_INSTANCES = new Set(["i-sandbox-1", "i-sandbox-2"]);
const server = new McpServer({ name: "infra", version: "1.0.0" });

server.registerTool(
  "terminateInstance",
  {
    description: "Terminate a sandbox VM",
    inputSchema: { instanceId: z.string() },
    annotations: { destructiveHint: true },
  },
  async ({ instanceId }) => {
    if (!ALLOWED_INSTANCES.has(instanceId)) {
      throw new Error("instance is not a sandbox");
    }
    await ec2.terminateInstances({ InstanceIds: [instanceId] });
    return { content: [{ type: "text", text: "terminated" }] };
  }
);
