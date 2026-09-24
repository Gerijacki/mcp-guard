package source

import (
	"regexp"
	"strconv"
	"strings"
	"unicode/utf16"
)

// This file contains a deliberately small, language-aware lexer. It is not a parser:
// it only knows enough about strings, comments and brackets to find matching
// delimiters, split call arguments and group lines into statements.

func isQuote(c byte, lang Language) bool {
	switch lang {
	case Python:
		return c == '"' || c == '\''
	case TypeScript, Go:
		return c == '"' || c == '\'' || c == '`'
	}
	return c == '"' || c == '\''
}

func isSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' }

func isIdentChar(c byte) bool {
	return c == '_' || c == '$' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

// SkipSpace returns the first offset >= i that is not whitespace (newlines included).
func SkipSpace(s string, i int) int { return skipSpace(s, i) }

func skipSpace(s string, i int) int {
	for i < len(s) && isSpace(s[i]) {
		i++
	}
	return i
}

// skipComment returns the offset just past a comment starting at i. The trailing
// newline of a line comment is not consumed.
func skipComment(s string, i int, lang Language) (int, bool) {
	switch lang {
	case Python, YAML, TOML, Env:
		if s[i] == '#' {
			if j := strings.IndexByte(s[i:], '\n'); j >= 0 {
				return i + j, true
			}
			return len(s), true
		}
	case TypeScript, Go, JSON:
		if i+1 < len(s) && s[i] == '/' {
			switch s[i+1] {
			case '/':
				if j := strings.IndexByte(s[i:], '\n'); j >= 0 {
					return i + j, true
				}
				return len(s), true
			case '*':
				if j := strings.Index(s[i+2:], "*/"); j >= 0 {
					return i + 2 + j + 2, true
				}
				return len(s), true
			}
		}
	}
	return i, false
}

// skipString returns the offset just past the string literal whose opening quote is at i.
func skipString(s string, i int, lang Language) int {
	q := s[i]
	if lang == Python && i+2 < len(s) && s[i+1] == q && s[i+2] == q {
		triple := s[i : i+3]
		for j := i + 3; j < len(s); j++ {
			if s[j] == '\\' {
				j++
				continue
			}
			if strings.HasPrefix(s[j:], triple) {
				return j + 3
			}
		}
		return len(s)
	}
	rawGo := lang == Go && q == '`'
	for j := i + 1; j < len(s); j++ {
		c := s[j]
		switch {
		case c == '\\' && !rawGo:
			j++
		case c == q:
			return j + 1
		case q == '`' && lang == TypeScript && c == '$' && j+1 < len(s) && s[j+1] == '{':
			end := MatchClose(s, j+1, lang)
			if end < 0 {
				return len(s)
			}
			j = end
		case c == '\n' && q != '`':
			return j // unterminated single-line string: stop at end of line
		}
	}
	return len(s)
}

// MatchClose returns the offset of the bracket matching the one at open, skipping
// strings and comments, or -1 if it is unbalanced.
func MatchClose(s string, open int, lang Language) int {
	depth := 0
	for i := open; i < len(s); {
		c := s[i]
		if end, ok := skipComment(s, i, lang); ok {
			i = end
			continue
		}
		if isQuote(c, lang) {
			i = skipString(s, i, lang)
			continue
		}
		switch c {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
			if depth == 0 {
				return i
			}
		}
		i++
	}
	return -1
}

// Segment is a half-open byte range [Start, End) of a larger string.
type Segment struct{ Start, End int }

// Text returns the trimmed text of the segment.
func (sg Segment) Text(s string) string { return strings.TrimSpace(s[sg.Start:sg.End]) }

// SplitArgs splits s[start:end] on top-level commas (e.g. the inside of a call's parentheses).
func SplitArgs(s string, start, end int, lang Language) []Segment {
	var out []Segment
	depth, segStart := 0, start
	for i := start; i < end; {
		c := s[i]
		if e, ok := skipComment(s, i, lang); ok {
			i = e
			continue
		}
		if isQuote(c, lang) {
			i = skipString(s, i, lang)
			continue
		}
		switch c {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case ',':
			if depth == 0 {
				out = append(out, Segment{segStart, i})
				segStart = i + 1
			}
		}
		i++
	}
	if strings.TrimSpace(s[segStart:end]) != "" {
		out = append(out, Segment{segStart, end})
	}
	return out
}

// ParseStringLiteral parses the string literal starting at (or after whitespace from)
// offset i. It handles Python prefixes/triple quotes/implicit concatenation,
// "a" + "b" concatenation, and escape sequences. It returns the decoded value and the
// offset just past the literal.
func ParseStringLiteral(s string, i int, lang Language) (string, int, bool) {
	i = skipSpace(s, i)
	if i >= len(s) {
		return "", i, false
	}
	if lang == Python && s[i] == '(' {
		if close := MatchClose(s, i, lang); close > 0 {
			if v, e, ok := ParseStringLiteral(s, i+1, lang); ok && skipSpace(s, e) == close {
				return v, close + 1, true
			}
		}
		return "", i, false
	}
	var sb strings.Builder
	found := false
	for {
		j := skipSpace(s, i)
		k, raw := j, false
		if lang == Python {
			for k < len(s) && k-j < 2 && strings.IndexByte("rRbBfFuU", s[k]) >= 0 {
				if s[k] == 'r' || s[k] == 'R' {
					raw = true
				}
				k++
			}
		}
		if k >= len(s) || !isQuote(s[k], lang) || (lang == Go && s[k] == '\'') {
			break
		}
		end := skipString(s, k, lang)
		q := 1
		if lang == Python && k+2 < len(s) && s[k+1] == s[k] && s[k+2] == s[k] {
			q = 3
		}
		inner := ""
		if end-q >= k+q {
			inner = s[k+q : end-q]
		}
		if raw || (lang == Go && s[k] == '`') {
			sb.WriteString(inner)
		} else {
			sb.WriteString(Unescape(inner))
		}
		found = true
		i = end
		n := skipSpace(s, i)
		if n < len(s) && s[n] == '+' {
			i = n + 1
			continue
		}
		if lang == Python {
			continue // implicit concatenation: "a" "b"
		}
		break
	}
	if !found {
		return "", i, false
	}
	return sb.String(), i, true
}

// Unescape decodes common backslash escapes shared by Python, JS and Go, including
// \uXXXX (with UTF-16 surrogate pairs), \u{...}, \UXXXXXXXX and \xXX.
func Unescape(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '\\' || i+1 >= len(s) {
			b.WriteByte(c)
			continue
		}
		i++
		switch s[i] {
		case 'n':
			b.WriteByte('\n')
		case 't':
			b.WriteByte('\t')
		case 'r':
			b.WriteByte('\r')
		case '\n':
			// line continuation
		case 'x':
			if r, ok := hexRune(s, i+1, 2); ok {
				b.WriteRune(r)
				i += 2
			} else {
				b.WriteByte('x')
			}
		case 'U':
			if r, ok := hexRune(s, i+1, 8); ok {
				b.WriteRune(r)
				i += 8
			} else {
				b.WriteByte('U')
			}
		case 'u':
			if i+1 < len(s) && s[i+1] == '{' {
				if end := strings.IndexByte(s[i:], '}'); end > 0 {
					if v, err := strconv.ParseUint(s[i+2:i+end], 16, 32); err == nil {
						b.WriteRune(rune(v))
						i += end
						continue
					}
				}
			}
			r, ok := hexRune(s, i+1, 4)
			if !ok {
				b.WriteByte('u')
				continue
			}
			i += 4
			if utf16.IsSurrogate(r) && i+6 < len(s)+1 && strings.HasPrefix(s[i+1:], `\u`) {
				if r2, ok := hexRune(s, i+3, 4); ok {
					if dec := utf16.DecodeRune(r, r2); dec != '�' {
						r = dec
						i += 6
					}
				}
			}
			b.WriteRune(r)
		default:
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

func hexRune(s string, i, n int) (rune, bool) {
	if i+n > len(s) {
		return 0, false
	}
	v, err := strconv.ParseUint(s[i:i+n], 16, 32)
	if err != nil {
		return 0, false
	}
	return rune(v), true
}

// Stmt is a logical statement: one or more physical lines joined while brackets are open.
type Stmt struct {
	Text    string // comments removed
	Line    int    // first line
	EndLine int
}

// Statements groups lines [startLine, endLine] into logical statements. Comments are
// stripped, multi-line calls are joined, and JS/Go block braces act as separators so
// that each statement inside a function body stays separate.
func (f *File) Statements(startLine, endLine int) []Stmt {
	return f.StatementsIn(f.LineStart(startLine), f.LineEnd(endLine))
}

// StatementsIn is like Statements for the byte range [start, end).
func (f *File) StatementsIn(start, end int) []Stmt {
	s, lang := f.Content, f.Language
	var (
		out       []Stmt
		b         strings.Builder
		depth     int
		stmtStart = -1
	)
	flush := func(at int) {
		if text := strings.TrimSpace(b.String()); text != "" && stmtStart >= 0 {
			out = append(out, Stmt{Text: text, Line: f.LineAt(stmtStart), EndLine: f.LineAt(at)})
		}
		b.Reset()
		stmtStart = -1
	}
	braceBlocks := lang == TypeScript || lang == Go
	for i := start; i < end; {
		c := s[i]
		if e, ok := skipComment(s, i, lang); ok {
			b.WriteByte(' ')
			i = min(e, end)
			continue
		}
		if isQuote(c, lang) {
			if stmtStart < 0 {
				stmtStart = i
			}
			e := min(skipString(s, i, lang), end)
			b.WriteString(s[i:e])
			i = e
			continue
		}
		if c == '\\' && i+1 < end && s[i+1] == '\n' {
			b.WriteByte(' ')
			i += 2
			continue
		}
		switch c {
		case '{':
			if braceBlocks && depth == 0 && isBlockBrace(s, i, lang) {
				b.WriteByte('{')
				flush(i)
				i++
				continue
			}
			depth++
		case '(', '[':
			depth++
		case ')', ']':
			if depth > 0 {
				depth--
			}
		case '}':
			if depth > 0 {
				depth--
			} else if braceBlocks {
				flush(i)
				i++
				continue
			}
		case '\n':
			if depth == 0 {
				flush(i)
				i++
				continue
			}
		case ';':
			if depth == 0 && lang != Python {
				flush(i)
				i++
				continue
			}
		}
		if stmtStart < 0 && !isSpace(c) {
			stmtStart = i
		}
		b.WriteByte(c)
		i++
	}
	flush(end)
	return out
}

// isBlockBrace guesses whether the '{' at i opens a code block (function body, if, for…)
// rather than an object/composite literal: it must end the line and follow ')' or a
// space-separated keyword/expression, but not '=', ':', ',', '(' or `return`.
func isBlockBrace(s string, i int, lang Language) bool {
	j := i + 1
	for j < len(s) && (s[j] == ' ' || s[j] == '\t' || s[j] == '\r') {
		j++
	}
	if j < len(s) && s[j] != '\n' {
		if _, ok := skipComment(s, j, lang); !ok {
			return false
		}
	}
	k := i - 1
	if k < 0 {
		return true
	}
	if s[k] != ' ' && s[k] != '\t' && s[k] != ')' {
		return false // Go composite literal: Type{
	}
	for k >= 0 && (s[k] == ' ' || s[k] == '\t') {
		k--
	}
	if k < 0 {
		return true
	}
	if strings.IndexByte("=:,([?&|", s[k]) >= 0 {
		return false
	}
	w := k
	for w >= 0 && isIdentChar(s[w]) {
		w--
	}
	return s[w+1:k+1] != "return"
}

// ContainsIdent reports whether name occurs in text as a standalone identifier that is
// not an attribute access (so "os.path" does not match "path").
func ContainsIdent(text, name string) bool {
	return IdentIndex(text, name) >= 0
}

// IdentIndex returns the offset of the first standalone occurrence of name in text, or -1.
func IdentIndex(text, name string) int {
	if name == "" {
		return -1
	}
	for off := 0; off < len(text); {
		i := strings.Index(text[off:], name)
		if i < 0 {
			return -1
		}
		i += off
		before := i == 0 || (!isIdentChar(text[i-1]) && text[i-1] != '.')
		after := i+len(name) >= len(text) || !isIdentChar(text[i+len(name)])
		if before && after {
			return i
		}
		off = i + len(name)
	}
	return -1
}

var identRe = regexp.MustCompile(`[A-Za-z_$][\w$]*`)

// Identifiers returns all identifier-like tokens in text.
func Identifiers(text string) []string { return identRe.FindAllString(text, -1) }

// Indent returns the indentation width of a line (tabs count as 4).
func Indent(line string) int {
	n := 0
	for _, c := range line {
		switch c {
		case ' ':
			n++
		case '\t':
			n += 4
		default:
			return n
		}
	}
	return n
}

// maskComments returns s with every comment replaced by spaces (newlines kept), so that
// byte offsets and line numbers are unchanged. String literals are preserved.
func maskComments(s string, lang Language) string {
	var b []byte
	for i := 0; i < len(s); {
		if end, ok := skipComment(s, i, lang); ok {
			if b == nil {
				b = []byte(s)
			}
			for j := i; j < end; j++ {
				if b[j] != '\n' {
					b[j] = ' '
				}
			}
			i = end
			continue
		}
		if isQuote(s[i], lang) {
			i = skipString(s, i, lang)
			continue
		}
		i++
	}
	if b == nil {
		return s
	}
	return string(b)
}
