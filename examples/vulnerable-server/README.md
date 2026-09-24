# Deliberately vulnerable MCP server

**Do not run or deploy this server.** It exists to show what mcp-guard catches. Every tool contains a real-world class of MCP vulnerability:

| Tool / file | Issue | Rule |
|---|---|---|
| `read_file` | Reads any path the model asks for | MCPG001 |
| `save_report` | `os.path.join("reports", filename)` does not stop `../` | MCPG001 |
| `summarize_url` | Returns raw web content to the model | MCPG002 |
| `WEATHER_SERVICE_TOKEN`, `mcp.json` | Hard-coded service token, bearer header and database password | MCPG003 |
| `run_diagnostics` | `subprocess.run(f"ping {host}", shell=True)` | MCPG004 |
| `find_employee` | f-string SQL query | MCPG005 |
| `purge_channel` | `destructiveHint: true` with no confirmation or limit | MCPG006 |
| `get_weather` | `<IMPORTANT>` block telling the model to leak `~/.ssh/id_rsa` | MCPG007 |
| `FastMCP(host="0.0.0.0")` | HTTP transport on all interfaces with no auth | MCPG008 |

```sh
mcp-guard scan examples/vulnerable-server
```

The credentials in this folder are fake and were never valid.
