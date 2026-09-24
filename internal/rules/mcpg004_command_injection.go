package rules

import (
	"fmt"
	"regexp"

	"github.com/Gerijacki/mcp-guard/internal/finding"
	"github.com/Gerijacki/mcp-guard/internal/source"
)

// MCPG004: a tool parameter reaches a shell, an interpreter or the program name of a process.
type commandInjectionRule struct{}

type sinkKind int

const (
	sinkShell   sinkKind = iota // parsed by a shell: metacharacters (;, |, $()) inject commands
	sinkCode                    // evaluated as code (eval/exec/new Function)
	sinkProgram                 // chooses which program runs (no shell, but still arbitrary execution)
)

type cmdSink struct {
	re       *regexp.Regexp
	requires *regexp.Regexp // extra evidence required in the statement (e.g. shell=True)
	kind     sinkKind
	argIndex int // for sinkProgram: which call argument names the program
}

var cmdSinks = map[source.Language][]cmdSink{
	source.Python: {
		{re: regexp.MustCompile(`\bos\.(?:system|popen)\s*\(|\bsubprocess\.(?:getoutput|getstatusoutput)\s*\(|\basyncio\.create_subprocess_shell\s*\(|\bcommands\.getoutput\s*\(`), kind: sinkShell},
		{re: regexp.MustCompile(`\bsubprocess\.(?:run|call|Popen|check_output|check_call)\s*\(`), requires: regexp.MustCompile(`\bshell\s*=\s*True\b`), kind: sinkShell},
		{re: regexp.MustCompile(`(?:^|[^.\w])(?:eval|exec)\s*\(`), kind: sinkCode},
		{re: regexp.MustCompile(`\bsubprocess\.(?:run|call|Popen|check_output|check_call)\s*\(|\basyncio\.create_subprocess_exec\s*\(|\bos\.exec[lv]p?e?\s*\(|\bos\.spawn[lv]p?e?\s*\(`), kind: sinkProgram},
	},
	source.TypeScript: {
		{re: regexp.MustCompile(`(?:^|[^.\w$])(?:exec|execSync|execAsync|execPromise|execP)\s*\(|\b(?:child_process|childProcess|cp)\.(?:exec|execSync)\s*\(|\bexecaCommand(?:Sync)?\s*\(|\bshell\.exec\s*\(`), kind: sinkShell},
		{re: regexp.MustCompile(`\b(?:spawn|spawnSync|execFile|execFileSync|execa|execaSync)\s*\(`), requires: regexp.MustCompile(`\bshell\s*:\s*(?:true|['"])`), kind: sinkShell},
		{re: regexp.MustCompile(`(?:^|[^.\w$])eval\s*\(|\bnew\s+Function\s*\(|\bvm\.run\w*\s*\(`), kind: sinkCode},
		{re: regexp.MustCompile(`\b(?:spawn|spawnSync|execFile|execFileSync|execa|execaSync)\s*\(`), kind: sinkProgram},
		{re: regexp.MustCompile(`\bBun\.spawn(?:Sync)?\s*\(`), kind: sinkProgram},
	},
	source.Go: {
		{re: regexp.MustCompile(`\bexec\.Command\s*\(`), requires: goShellRe, kind: sinkShell},
		{re: regexp.MustCompile(`\bexec\.CommandContext\s*\(`), requires: goShellRe, kind: sinkShell},
		{re: regexp.MustCompile(`\bexec\.Command\s*\(`), kind: sinkProgram, argIndex: 0},
		{re: regexp.MustCompile(`\bexec\.CommandContext\s*\(`), kind: sinkProgram, argIndex: 1},
	},
}

var (
	goShellRe = regexp.MustCompile(`"(?:/bin/|/usr/bin/)?(?:sh|bash|zsh|dash|ash)"\s*,\s*"-c"|"cmd(?:\.exe)?"\s*,\s*"/[cCkK]"|"(?:powershell|pwsh)(?:\.exe)?"`)
	// Quoting helpers that make a value safe to embed in a shell command.
	shellQuoteRe = regexp.MustCompile(`\bshlex\.(?:quote|join)\s*\(|\bshellescape|\bshell-?quote|\bquote\s*\(|\bescapeShellArg\s*\(|\bshellwords\b|\bshellescape\.Quote\s*\(`)
	// Evidence that the program is restricted to an allowlist.
	commandAllowlistRe = regexp.MustCompile(`(?i)allow(?:ed)?[_-]?(?:list|commands?|cmds?|programs?|binaries|executables)|whitelist|\bin\s+[A-Z][A-Z0-9_]{2,}\b|\b[A-Z][A-Z0-9_]{2,}\.(?:includes|has)\s*\(|slices\.Contains\s*\(\s*[A-Z]\w*|\bnot\s+in\s+[A-Z]`)
)

func (commandInjectionRule) Meta() Meta {
	return Meta{
		ID:       "MCPG004",
		Name:     "command-injection",
		Severity: finding.Critical,
		Summary:  "Tool parameter reaches a shell, eval or process execution",
		Description: "A model-controlled value is interpolated into a shell command (os.system, " +
			"subprocess(shell=True), child_process.exec, sh -c), evaluated as code, or used as the " +
			"program to execute. Because tool arguments come from the LLM, anyone who can influence " +
			"the conversation or the content the model reads can run arbitrary commands on the host.",
		Remediation: "Never build shell strings from tool input. Execute a fixed program with an argument " +
			"list (subprocess.run([...]) without shell=True, execFile/spawn without shell, exec.Command " +
			"with separate args), validate arguments against an allowlist, and pass user values after " +
			"'--' so they cannot become flags. Remove eval/exec of tool input entirely.",
		CWE: []string{"CWE-78", "CWE-94"},
	}
}

func (r commandInjectionRule) Check(f *source.File) []finding.Finding {
	sinks := cmdSinks[f.Language]
	if sinks == nil {
		return nil
	}
	var out []finding.Finding
	for _, t := range toolBodies(f) {
		allowlisted := commandAllowlistRe.MatchString(f.BodyText(t))
		walkTaint(f, t, shellQuoteRe, func(st source.Stmt, taint *taintSet) {
			for _, s := range sinks {
				loc := s.re.FindStringIndex(st.Text)
				if loc == nil || (s.requires != nil && !s.requires.MatchString(st.Text)) {
					continue
				}
				args := st.Text[loc[0]:]
				var p string
				switch s.kind {
				case sinkShell, sinkCode:
					if shellQuoteRe.MatchString(args) {
						return
					}
					p = taint.find(args)
				case sinkProgram:
					if allowlisted {
						continue
					}
					open := loc[1] - 1
					callArgsList := callArgs(st.Text, open, f.Language)
					if s.argIndex < len(callArgsList) {
						p = taint.find(firstElement(callArgsList[s.argIndex], f.Language))
					}
				}
				if p == "" {
					continue
				}
				sev, msg := finding.Critical, ""
				switch s.kind {
				case sinkShell:
					msg = fmt.Sprintf("Tool %q interpolates model-controlled %q into a shell command (command injection).", t.Name, p)
				case sinkCode:
					msg = fmt.Sprintf("Tool %q evaluates model-controlled %q as code (code injection).", t.Name, p)
				case sinkProgram:
					sev = finding.High
					msg = fmt.Sprintf("Tool %q lets the model choose the program to execute via %q without an allowlist.", t.Name, p)
				}
				out = append(out, newFinding(r.Meta(), f, st.Line, sev, t.Name, msg))
				return // one finding per statement
			}
		})
	}
	return out
}
