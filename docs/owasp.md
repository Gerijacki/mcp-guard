# OWASP mapping

Every mcp-guard rule is mapped to three OWASP lists:

- [**OWASP MCP Top 10**](https://owasp.org/www-project-mcp-top-10/) (`MCP01`–`MCP10`, 2025). The project is in beta, so titles and rankings may still change.
- [**OWASP Top 10 for LLM Applications 2025**](https://genai.owasp.org/llm-top-10/) (`LLM01`–`LLM10`).
- [**OWASP Top 10 for Agentic Applications 2026**](https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/) (`ASI01`–`ASI10`).

These IDs appear in three places:

- `mcp-guard rules explain <ID>`
- the SARIF rule tags, as `external/owasp/mcp05:2025` and so on, so you can filter by them in GitHub code scanning
- the header of each rule's documentation page

| Rule | OWASP MCP Top 10 | LLM Top 10 (2025) | Agentic Top 10 (2026) |
|---|---|---|---|
| [MCPG001](rules/MCPG001.md) unrestricted-file-access | MCP02 Privilege Escalation via Scope Creep | LLM06 Excessive Agency | ASI02 Tool Misuse |
| [MCPG002](rules/MCPG002.md) untrusted-content-passthrough | MCP06 Prompt Injection via Contextual Payloads | LLM01 Prompt Injection | ASI01 Agent Goal Hijack |
| [MCPG003](rules/MCPG003.md) hardcoded-secret | MCP01 Token Mismanagement & Secret Exposure | LLM02 Sensitive Information Disclosure | ASI03 Identity & Privilege Abuse |
| [MCPG004](rules/MCPG004.md) command-injection | MCP05 Command Injection & Execution | LLM05 Improper Output Handling | ASI05 Unexpected Code Execution |
| [MCPG005](rules/MCPG005.md) sql-injection | MCP05 Command Injection & Execution | LLM05 Improper Output Handling | ASI02 Tool Misuse |
| [MCPG006](rules/MCPG006.md) unscoped-destructive-tool | MCP02 Privilege Escalation via Scope Creep | LLM06 Excessive Agency | ASI02 Tool Misuse |
| [MCPG007](rules/MCPG007.md) tool-poisoning | MCP03 Tool Poisoning | LLM01 Prompt Injection | ASI01 Agent Goal Hijack, ASI04 Agentic Supply Chain Vulnerabilities |
| [MCPG008](rules/MCPG008.md) exposed-network-transport | MCP07 Insufficient Authentication & Authorization | none | ASI03 Identity & Privilege Abuse |

## Rationale

- **MCPG001.** A tool that reads or writes any path the model supplies gives the agent more reach than it needs. A single injected instruction turns that reach into data theft or file tampering.
- **MCPG002.** Content fetched from the web or third-party APIs can carry instructions. Returning it to the model unmarked is the classic *indirect* prompt-injection path.
- **MCPG003.** Credentials hardcoded in servers, client configs or `.env` files leak through the repository and through the model's context.
- **MCPG004, MCPG005.** Model output (tool arguments) flows into a shell, `eval` or a SQL string without validation. Both LLM05 and MCP05 describe this: untrusted model output handled as code. SQL injection is the database form of the same problem. It lets the agent misuse the tool (ASI02), rather than execute code on the host.
- **MCPG006.** Destructive tools with no confirmation, allowlist or limit are excessive agency by definition.
- **MCPG007.** Instructions hidden in tool descriptions are the canonical MCP tool-poisoning attack. A third-party server that ships them is a supply-chain risk for every agent that installs it.
- **MCPG008.** An HTTP/SSE transport bound to all interfaces without authentication lets anyone on the network call the tools. This is an authentication failure rather than a model-level risk, so there is no LLM Top 10 entry.

## Not covered

mcp-guard is a static analyzer for server code and client configs. Several OWASP risks are runtime or organizational concerns that it does not attempt to detect:

- MCP08 Lack of Audit and Telemetry
- MCP09 Shadow MCP Servers
- ASI07 Insecure Inter-Agent Communication
- ASI08 Cascading Failures
- ASI10 Rogue Agents

The [roadmap](../README.md#roadmap) mentions checks that would extend coverage of MCP04, LLM03 and ASI04 (unpinned `npx -y` packages in client configs).

Custom rules can declare their own mapping with the `owasp` field. See [custom-rules.md](custom-rules.md).
