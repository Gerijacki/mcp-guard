import https from "node:https";
import fs from "node:fs";

export const agent = new https.Agent({ ca: fs.readFileSync("corp-ca.pem"), rejectUnauthorized: true });
