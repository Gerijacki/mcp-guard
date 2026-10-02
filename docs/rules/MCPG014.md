# MCPG014: tls-verification-disabled

**Default severity:** medium · **CWE:** [CWE-295](https://cwe.mitre.org/data/definitions/295.html) · **OWASP:** [MCP07, ASI03](../owasp.md)

Certificate or hostname verification is switched off: `verify=False`, `ssl._create_unverified_context()`, `check_hostname = False`, `rejectUnauthorized: false`, `NODE_TLS_REJECT_UNAUTHORIZED=0`, `InsecureSkipVerify: true`. Anyone on the network path can impersonate the remote service, read the credentials the server sends, and rewrite the responses that reach the model.

## Vulnerable

```python
resp = httpx.get(url, verify=False)
```

## Fixed

```python
resp = httpx.get(url, verify="/etc/ssl/certs/corp-ca.pem")   # private CA
resp = httpx.get(url)                                        # system CAs
```

## How it is detected

The patterns above in code (comments are ignored). Lines that mention `localhost` or `127.0.0.1` are skipped, since self-signed local dev certificates are common. At most three findings are reported per file.
