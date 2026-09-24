# Rendered in CI by .github/workflows/demo.yml (VHS: https://github.com/charmbracelet/vhs)
Output docs/demo.gif

Set Shell "bash"
Set FontSize 15
Set Width 1280
Set Height 760
Set Padding 24
Set Theme "Catppuccin Mocha"
Set TypingSpeed 35ms
Set WindowBar Colorful

Hide
Type "export PS1='$ ' && clear" Enter
Show

Type "# An MCP server with a few very common mistakes:" Enter
Sleep 600ms
Type "ls examples/vulnerable-server" Enter
Sleep 1s
Type "mcp-guard scan examples/vulnerable-server" Sleep 400ms Enter
Sleep 7s

Type "clear" Enter
Type "# Every finding links to an explanation and a fix:" Enter
Type "mcp-guard rules explain MCPG007 | head -n 12" Sleep 400ms Enter
Sleep 5s

Type "clear" Enter
Type "# CI-friendly: SARIF for GitHub code scanning, exit code 1 on findings" Enter
Type "mcp-guard scan examples/vulnerable-server --format sarif -o report.sarif; echo exit=$?" Sleep 400ms Enter
Sleep 2500ms
Type "rm report.sarif" Enter
Sleep 1s
