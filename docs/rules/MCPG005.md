# MCPG005: sql-injection

**Default severity:** high · **CWE:** [CWE-89](https://cwe.mitre.org/data/definitions/89.html)

The tool builds a SQL statement with f-strings, `%` formatting, `.format`, concatenation, template literals or `fmt.Sprintf` using a model-controlled value. The model (or an injection) can then read or modify any table the database user can reach: `' OR 1=1 --`, `'; DROP TABLE users; --`. Database MCP servers are popular and often connected with powerful credentials.

## Vulnerable

```python
query = f"SELECT id, email FROM users WHERE name = '{name}'"
conn.execute(query)
```

```ts
await pool.query(`SELECT id FROM users WHERE email = '${email}'`);
```

```go
q := fmt.Sprintf("SELECT id FROM users WHERE name = '%s'", name)
db.QueryContext(ctx, q)
```

## Fixed

```python
conn.execute("SELECT id, email FROM users WHERE name = ?", (name,))
```

```ts
await pool.query("SELECT id FROM users WHERE email = $1", [email]);
```

```go
db.QueryContext(ctx, "SELECT id FROM users WHERE name = ?", name)
```

Validate identifiers such as table and column names against an allowlist, since they cannot be parameterized, and connect with a least-privilege, ideally read-only, database user. If the tool must run arbitrary model-written SQL, run it against a read-only replica with row limits and timeouts.

## How it is detected

A statement containing SQL keywords, string interpolation and a tainted value, either passed directly to a query sink (`execute`, `executescript`, `query`, `raw`, `$queryRawUnsafe`, `Exec`, `Query`, `QueryRow`, …) or assigned to a variable that later reaches one. Safe tagged templates (`sql\`...\``, Prisma `$queryRaw\`...\``) are ignored.
