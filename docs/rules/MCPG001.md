# MCPG001: unrestricted-file-access

**Default severity:** high (writes/deletes), medium (reads) · **CWE:** [CWE-22](https://cwe.mitre.org/data/definitions/22.html), [CWE-73](https://cwe.mitre.org/data/definitions/73.html) · **OWASP:** [MCP02, LLM06, ASI02](../owasp.md)

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

Details that keep it precise:

- The evidence is looked up in the handler's code only: a comment or docstring saying "validates the path" does not count.
- A `startswith` / `startsWith` / `HasPrefix` check only counts when the value was normalized first (`resolve`, `realpath`, `abspath`, `filepath.Clean`…) and the check mentions the tainted value: `"/srv/data/../../etc/passwd".startswith("/srv/data")` is true.
- Idioms that reduce a value to a harmless component are sanitizers: `os.path.basename`, `Path(p).name`, `filepath.Base`, `secure_filename`, `filepath.Clean("/" + p)`.
- A clean reassignment (`path = "/srv/default.txt"`) at the top level of the handler clears the taint.
- When the tool hands the value to a helper function (same file, or another file when the call is unambiguous), the helper is analyzed with that value tainted and the finding is reported at the real sink (`tool (via helper)`). Checks done in the caller protect the helper.
- Your own helpers can be declared in `.mcp-guard.yaml` under `extend:` (see [custom rules](../custom-rules.md)).
