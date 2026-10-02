# MCPG015: oauth-scope-or-token-misuse

**Default severity:** medium · **CWE:** [CWE-269](https://cwe.mitre.org/data/definitions/269.html), [CWE-285](https://cwe.mitre.org/data/definitions/285.html) · **OWASP:** [MCP02, LLM06, ASI03](../owasp.md)

Two OAuth mistakes in MCP servers:

1. **Wildcard or administrator scopes** (`scopes = "* admin"`, `.default`, `full_access`): every prompt injection becomes account-wide access.
2. **Token passthrough:** the access token the server received from the MCP client is forwarded to a downstream API. The MCP authorization specification forbids this: the downstream service cannot tell the token was issued for another audience, audit trails break, and a compromised server can replay the token.

## Vulnerable

```python
token = ctx.request_context.request.headers.get("authorization")
resp = await httpx.AsyncClient().get(API, headers={"Authorization": token})
```

## Fixed

```python
resp = await httpx.AsyncClient().get(API, headers={"Authorization": "Bearer " + os.environ["UPSTREAM_TOKEN"]})
```

Validate that incoming tokens were issued for this server (audience), and use token exchange or the server's own credentials for downstream calls.

## How it is detected

A `scope`/`scopes`/`required_scopes` literal containing `*`, `admin`, `full_access`, `.default` or `root`, and an outbound HTTP call whose headers come from the incoming request's `Authorization` header (directly or through a variable).
