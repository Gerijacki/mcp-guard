# MCPG001: unrestricted-file-access

**Default severity:** high (writes/deletes), medium (reads) · **CWE:** [CWE-22](https://cwe.mitre.org/data/definitions/22.html), [CWE-73](https://cwe.mitre.org/data/definitions/73.html)

A tool passes a model-controlled path straight to a filesystem API. The LLM (or a prompt injection it has read) chooses the value, so it can use absolute paths or `../` to read, overwrite or delete any file the server can reach: SSH keys, cloud credentials, other MCP client configs, source code.

## Vulnerable

```python
@mcp.tool()
def save_report(filename: str, content: str) -> str:
    target = os.path.join("reports", filename)   # "../../home/me/.bashrc" escapes
    with open(target, "w") as fh:
        fh.write(content)
```

```ts
server.tool("save_file", "Save a file", { filePath: z.string(), data: z.string() },
  async ({ filePath, data }) => { await fs.writeFile(filePath, data); /* ... */ });
```

## Fixed

```python
ROOT = Path("/srv/reports").resolve()

@mcp.tool()
def save_report(filename: str, content: str) -> str:
    target = (ROOT / filename).resolve()          # resolves "..", symlinks
    if not target.is_relative_to(ROOT):
        raise ValueError("path escapes the reports directory")
    target.write_text(content)
```

```ts
const target = path.resolve(ROOT, filePath);
const rel = path.relative(ROOT, target);
if (rel.startsWith("..") || path.isAbsolute(rel)) throw new Error("path escapes the workspace");
```

```go
root, err := os.OpenRoot("/srv/reports") // Go 1.24+: all access is confined to the root
f, err := root.Create(name)
```

## How it is detected

Inside each tool handler, values derived from tool parameters are followed through assignments to filesystem sinks (`open(..., "w")`, `os.remove`, `shutil.rmtree`, `fs.writeFile`, `fs.unlink`, `os.WriteFile`, `os.ReadFile`, …). The finding is dropped when the handler contains a containment check such as `is_relative_to`, `commonpath`, `startswith`/`startsWith`, `path.relative`, `filepath.IsLocal`, `filepath.Rel`, `os.OpenRoot`, `secure_filename` or a helper named like `safe_path`/`validate_path`.

**Limitations:** a check done in another function that the handler calls is only recognized if its name matches the patterns above.
