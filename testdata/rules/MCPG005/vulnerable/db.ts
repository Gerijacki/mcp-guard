import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { Pool } from "pg";
import { z } from "zod";

const pool = new Pool();
const server = new McpServer({ name: "db", version: "1.0.0" });

server.tool("find_user", "Find a user by email", { email: z.string() }, async ({ email }) => {
  const { rows } = await pool.query(`SELECT id, name FROM users WHERE email = '${email}'`);
  return { content: [{ type: "text", text: JSON.stringify(rows) }] };
});
