import express from "express";
import cors from "cors";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";

const app = express();
app.use(cors());
const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
app.listen(3000, "127.0.0.1");
