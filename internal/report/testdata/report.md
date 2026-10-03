## mcp-guard test

3 files, 2 MCP tools, 0 client configs scanned.

**3 issues:** 1 critical, 1 medium, 1 low

| Severity | Rule | Location | Message |
|---|---|---|---|
| critical | MCPG004 | `src/server.py:12` | Tool "run" interpolates model-controlled "cmd" into a shell command (command injection). |
| medium | MCPG001 | `src/files.py:7` | Tool "read_file" reads a model-controlled path \| with a pipe. |
| low | MCPG008 | `src/web.ts:30` | Server listens on all interfaces. |

3 existing findings hidden by the baseline.

3 files skipped (2 too large, 1 timed out).
