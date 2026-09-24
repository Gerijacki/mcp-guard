# MCPG008: exposed-network-transport

**Default severity:** medium · **CWE:** [CWE-306](https://cwe.mitre.org/data/definitions/306.html), [CWE-1327](https://cwe.mitre.org/data/definitions/1327.html)

The server exposes MCP over HTTP or SSE on all network interfaces (`0.0.0.0`, `::`, Go's `":8080"`, Node's `app.listen(port)` without a host), and no authentication is visible in the file. Anyone on the same network, or on the internet if the port is reachable, can list and call its tools directly, bypassing the client's confirmation prompts. Servers bound only to localhost without Origin checks are also exposed to DNS-rebinding attacks from malicious web pages.

## Vulnerable

```python
mcp = FastMCP("remote", host="0.0.0.0", port=8000)
mcp.run(transport="streamable-http")
```

```go
sse := server.NewSSEServer(s)
sse.Start(":8080")
```

## Fixed

For local use, bind to loopback:

```python
mcp = FastMCP("local", host="127.0.0.1", port=8000)
```

For remote servers, require authentication on every request (the [MCP authorization spec](https://modelcontextprotocol.io/specification/draft/basic/authorization) uses OAuth 2.1; at minimum a bearer token), validate the `Origin` and `Host` headers, and terminate TLS in front of the server.

```ts
app.post("/mcp", requireBearerAuth({ verifier }), handler);
```

## How it is detected

Files that use an HTTP/SSE MCP transport, bind to all interfaces, and contain no sign of authentication (`auth`, `bearer`, `api_key`, `jwt`, `oauth`, `TokenVerifier`, `requireAuth`, …). Because auth is often configured in another file, this rule is medium severity; suppress it with `mcp-guard:ignore MCPG008` when a reverse proxy handles authentication.
