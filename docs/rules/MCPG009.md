# MCPG009: server-side-request-forgery

**Default severity:** high (critical when redirects are followed) · **CWE:** [CWE-918](https://cwe.mitre.org/data/definitions/918.html) · **OWASP:** [MCP02, LLM06, ASI02](../owasp.md)

A tool parameter decides the URL (or just the host) of an HTTP request the *server* makes. The model, or a prompt injection it has read, can aim the server at things only the server can reach: cloud metadata (`http://169.254.169.254/`), `localhost` admin panels, databases, other MCP servers. The response comes back to the model, so the attacker can read it.

## Vulnerable

```python
@mcp.tool()
async def fetch_url(url: str) -> str:
    async with httpx.AsyncClient() as client:
        resp = await client.get(url, follow_redirects=True)
    return resp.text
```

## Fixed

```python
ALLOWED_HOSTS = {"api.example.com", "docs.example.com"}

@mcp.tool()
async def fetch_doc(url: str) -> str:
    if urlparse(url).hostname not in ALLOWED_HOSTS:
        raise ValueError("host not allowed")
    async with httpx.AsyncClient(follow_redirects=False) as client:
        return (await client.get(url)).text
```

Better still, build the URL from a constant base and pass the model's value only as a path or query component. If arbitrary URLs are the point of the tool, resolve the host and refuse private, loopback and link-local addresses, and re-check after every redirect.

## How it is detected

A tainted parameter reaches the URL argument of `requests`/`httpx`/`aiohttp`/`urllib` calls, `fetch`/`axios`/`got`/`undici`, or Go's `http.Get`/`http.NewRequest`. When the URL starts with a literal origin (`"https://api.example.com/" + id`) only the authority counts, so the usual "constant host, variable path" is not reported. A handler that mentions an allowlist, a private-address check or an SSRF helper is skipped.
