package rules

import (
	"fmt"
	"regexp"

	"github.com/Gerijacki/mcp-guard/internal/finding"
	"github.com/Gerijacki/mcp-guard/internal/source"
)

// MCPG005: a SQL query is built by string interpolation of a tool parameter.
type sqlInjectionRule struct{ ext extension }

var (
	sqlSinks = compileByLang(map[source.Language]string{
		source.Python:     `\.(?:execute|executemany|executescript|exec_driver_sql|raw|read_sql|read_sql_query|sql)\s*\(|\btext\s*\(`,
		source.TypeScript: `\.(?:query|execute|exec|raw|unsafe|\$queryRawUnsafe|\$executeRawUnsafe|prepare|all|get|run)\s*\(`,
		source.Go:         `\.(?:Exec|Query|QueryRow|ExecContext|QueryContext|QueryRowContext|Raw|Prepare|PrepareContext|Select|Get)\s*\(`,
	})
	sqlKeywordRe = regexp.MustCompile(`(?i)\bSELECT\s[\s\S]*?\bFROM\b|\bINSERT\s+INTO\b|\bUPDATE\s+\S+\s+SET\b|\bDELETE\s+FROM\b|\bDROP\s+(?:TABLE|DATABASE)\b|\bCREATE\s+TABLE\b|\bALTER\s+TABLE\b|\bWHERE\s+\w+\s*(?:=|LIKE|IN|<|>)|\bORDER\s+BY\b|\bGROUP\s+BY\b`)
	// String building: f-strings, %-formatting, .format, concatenation, template literals, Sprintf.
	sqlInterpRe = regexp.MustCompile(`(?:^|[^\w])f["']|["'` + "`" + `]\s*%\s*[\w(]|\.format\s*\(|["'` + "`" + `]\s*\+|\+\s*["'` + "`" + `]|\$\{|\bSprintf\s*\(|\.concat\s*\(|\+=\s*f?["']`)
	// Casts and identifier quoting turn a model value into something that cannot carry SQL.
	sqlSanitizerRe = regexp.MustCompile(`(?:^|[^.\w])(?:int|float|bool|Number|parseInt|parseFloat|Boolean)\s*\(|\bstrconv\.(?:Atoi|ParseInt|ParseUint|ParseFloat|ParseBool)\s*\(|\bUUID\s*\(|\b(?:quote_ident|quoteIdent|escapeId|escapeIdentifier)\s*\(|\b(?:sql|pgx)\.Identifier\b|\bIdentifier\s*\(`)
	// An allowlist/membership test on a value (table names, sort columns) validates it.
	sqlAllowRe = regexp.MustCompile(`(?i)\bnot\s+in\s+\w|\bin\s+[A-Z][A-Z0-9_]{2,}\b|\b[A-Z][A-Z0-9_]{2,}\.(?:includes|has|get)\s*\(|\bslices\.Contains\s*\(|allow(?:ed)?[_-]?(?:list|tables?|columns?|fields?|sort)|whitelist|\.includes\s*\(`)
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
	return r.CheckTools(f, taintBodies(f))
}

// CheckTools runs the rule on the given tools (the file's tools plus helper views).
func (r sqlInjectionRule) CheckTools(f *source.File, tools []source.Tool) []finding.Finding {
	sink := sqlSinks[f.Language]
	if sink == nil {
		return nil
	}
	if r.ext.sinks != nil {
		sink = regexp.MustCompile("(?:" + sink.String() + ")|" + r.ext.sinks.String())
	}
	sanitizer := r.ext.withSanitizers(sqlSanitizerRe)
	var out []finding.Finding
	for _, t := range tools {
		sqlVars := newTaintSet(nil) // variables holding SQL built from tainted input
		sqlText := newTaintSet(nil) // variables holding SQL text (possibly constant)
		walkTaint(f, t, sanitizer, func(st source.Stmt, taint *taintSet) {
			text := st.Text
			if sqlAllowRe.MatchString(text) {
				// `if table not in ALLOWED: raise` validates every tainted name it mentions.
				for _, id := range append([]string(nil), taint.order...) {
					if taint.has[id] && source.ContainsIdent(text, id) {
						taint.remove(id)
					}
				}
			}
			if loc := sink.FindStringIndex(text); loc != nil {
				// Only the query argument matters: values bound as parameters are safe, and
				// interpolating a constant (a table name) is not injection.
				query := text[loc[0]:]
				if args := callArgs(text, loc[1]-1, f.Language); len(args) > 0 {
					query = args[0]
					if len(args) > 1 && sqlCtxArg.MatchString(text[loc[0]:loc[1]]) {
						query = args[1]
					}
				}
				p := ""
				if isSQLText(query, sqlText) && sqlInterpRe.MatchString(query) && !safeSQLTagRe.MatchString(query) {
					p = taint.find(query)
				}
				if p == "" {
					p = sqlVars.find(query)
				}
				if p != "" {
					out = append(out, newFinding(r.Meta(), f, st.Line, finding.High, t.Name, fmt.Sprintf(
						"%s %q executes SQL built by string interpolation of model-controlled input (via %q): SQL injection.", t.Noun(), t.Name, p)))
				}
				return
			}
			ids, rhs, ok := assignment(text)
			if !ok {
				return
			}
			if sqlKeywordRe.MatchString(rhs) {
				for _, id := range ids {
					sqlText.add(id)
				}
			}
			if isSQLText(text, sqlText) && sqlInterpRe.MatchString(text) && !safeSQLTagRe.MatchString(text) && taint.find(rhs) != "" {
				for _, id := range ids {
					sqlVars.add(id)
				}
			}
		})
	}
	return out
}

// sqlCtxArg matches sink names whose first argument is a context, so the query is second.
var sqlCtxArg = regexp.MustCompile(`Context\s*\($`)

// isSQLText reports whether text looks like SQL: it has SQL keywords, or it mentions a
// variable that already holds SQL (so that `q += f" ORDER BY {x}"` is recognized).
func isSQLText(text string, sqlText *taintSet) bool {
	return sqlKeywordRe.MatchString(text) || sqlText.find(text) != ""
}
