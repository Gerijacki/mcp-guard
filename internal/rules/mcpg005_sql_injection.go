package rules

import (
	"fmt"
	"regexp"

	"github.com/Gerijacki/mcp-guard/internal/finding"
	"github.com/Gerijacki/mcp-guard/internal/source"
)

// MCPG005: a SQL query is built by string interpolation of a tool parameter.
type sqlInjectionRule struct{}

var (
	sqlSinks = compileByLang(map[source.Language]string{
		source.Python:     `\.(?:execute|executemany|executescript|exec_driver_sql|raw|read_sql|read_sql_query|sql)\s*\(|\btext\s*\(`,
		source.TypeScript: `\.(?:query|execute|exec|raw|unsafe|\$queryRawUnsafe|\$executeRawUnsafe|prepare|all|get|run)\s*\(`,
		source.Go:         `\.(?:Exec|Query|QueryRow|ExecContext|QueryContext|QueryRowContext|Raw|Prepare|PrepareContext|Select|Get)\s*\(`,
	})
	sqlKeywordRe = regexp.MustCompile(`(?i)\bSELECT\s[\s\S]*?\bFROM\b|\bINSERT\s+INTO\b|\bUPDATE\s+\S+\s+SET\b|\bDELETE\s+FROM\b|\bDROP\s+(?:TABLE|DATABASE)\b|\bCREATE\s+TABLE\b|\bALTER\s+TABLE\b|\bWHERE\s+\w+\s*(?:=|LIKE|IN|<|>)`)
	// String building: f-strings, %-formatting, .format, concatenation, template literals, Sprintf.
	sqlInterpRe = regexp.MustCompile(`(?:^|[^\w])f["']|["'` + "`" + `]\s*%\s*[\w(]|\.format\s*\(|["'` + "`" + `]\s*\+|\+\s*["'` + "`" + `]|\$\{|\bSprintf\s*\(|\.concat\s*\(|\+=\s*f?["']`)
	// Tagged templates that parameterize automatically (postgres.js, slonik, Prisma $queryRaw``).
	safeSQLTagRe = regexp.MustCompile("\\b(?:sql|\\$queryRaw|\\$executeRaw|SQL)\\s*`")
)

func (sqlInjectionRule) Meta() Meta {
	return Meta{
		ID:       "MCPG005",
		Name:     "sql-injection",
		Severity: finding.High,
		Summary:  "SQL query built by string interpolation of a tool parameter",
		Description: "The tool builds a SQL statement with f-strings, concatenation, template literals or " +
			"Sprintf using a model-controlled value. The model (or a prompt injection) can then read or " +
			"modify any table the database user can reach, for example with ' OR 1=1 -- or ; DROP TABLE.",
		Remediation: "Use parameterized queries (cursor.execute(\"... WHERE id = ?\", (id,)), " +
			"db.query(\"... $1\", [id]), db.Query(\"... ?\", id)). Validate identifiers such as table or " +
			"column names against an allowlist, and connect with a least-privilege (ideally read-only) user.",
		CWE:   []string{"CWE-89"},
		OWASP: []string{"MCP05:2025", "LLM05:2025", "ASI02:2026"},
	}
}

func (r sqlInjectionRule) Check(f *source.File) []finding.Finding {
	sink := sqlSinks[f.Language]
	if sink == nil {
		return nil
	}
	var out []finding.Finding
	for _, t := range toolBodies(f) {
		sqlVars := newTaintSet(nil) // variables holding SQL built from tainted input
		walkTaint(f, t, nil, func(st source.Stmt, taint *taintSet) {
			text := st.Text
			builds := ""
			if sqlKeywordRe.MatchString(text) && sqlInterpRe.MatchString(text) && !safeSQLTagRe.MatchString(text) {
				builds = taint.find(text)
			}
			if loc := sink.FindStringIndex(text); loc != nil {
				p := builds
				if p == "" {
					p = sqlVars.find(text[loc[0]:])
				}
				if p != "" {
					out = append(out, newFinding(r.Meta(), f, st.Line, finding.High, t.Name, fmt.Sprintf(
						"Tool %q executes SQL built by string interpolation of model-controlled input (via %q): SQL injection.", t.Name, p)))
				}
				return
			}
			if builds != "" {
				if ids, _, ok := assignment(text); ok {
					for _, id := range ids {
						sqlVars.add(id)
					}
				}
			}
		})
	}
	return out
}
