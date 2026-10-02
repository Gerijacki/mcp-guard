package extract

import (
	"strings"
	"unicode"
)

// parseTOML is a small TOML reader for client configs such as Codex's config.toml:
// [tables] and [dotted.tables], key = value with strings, numbers, booleans, arrays and inline
// tables. It returns a nested map, or nil when the document is not understood. It does not try
// to be a conformant parser: it only has to read the shape of MCP server entries.
func parseTOML(src string) map[string]any {
	root := map[string]any{}
	cur := root
	lines := strings.Split(strings.ReplaceAll(src, "\r\n", "\n"), "\n")
	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(stripTOMLComment(lines[i]))
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[[") { // arrays of tables are not used by MCP configs
			cur = map[string]any{}
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			cur = root
			for _, part := range splitTOMLKey(strings.TrimSpace(line[1 : len(line)-1])) {
				next, ok := cur[part].(map[string]any)
				if !ok {
					next = map[string]any{}
					cur[part] = next
				}
				cur = next
			}
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq < 0 {
			continue
		}
		key := splitTOMLKey(strings.TrimSpace(line[:eq]))
		if len(key) == 0 {
			continue
		}
		val := strings.TrimSpace(line[eq+1:])
		// Arrays and inline tables may continue on the following lines.
		for depthOf(val) > 0 && i+1 < len(lines) {
			i++
			val += " " + strings.TrimSpace(stripTOMLComment(lines[i]))
		}
		target := cur
		for _, part := range key[:len(key)-1] {
			next, ok := target[part].(map[string]any)
			if !ok {
				next = map[string]any{}
				target[part] = next
			}
			target = next
		}
		v, _ := parseTOMLValue(val)
		target[key[len(key)-1]] = v
	}
	return root
}

// stripTOMLComment removes a trailing "# comment" that is not inside a string.
func stripTOMLComment(s string) string {
	var quote rune
	for i, r := range s {
		switch {
		case quote != 0:
			if r == quote && (i == 0 || s[i-1] != '\\' || quote == '\'') {
				quote = 0
			}
		case r == '"' || r == '\'':
			quote = r
		case r == '#':
			return s[:i]
		}
	}
	return s
}

// splitTOMLKey splits a dotted key, honoring quoted parts ("a.b".c).
func splitTOMLKey(k string) []string {
	var parts []string
	var cur strings.Builder
	var quote rune
	for _, r := range k {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			} else {
				cur.WriteRune(r)
			}
		case r == '"' || r == '\'':
			quote = r
		case r == '.':
			parts = append(parts, strings.TrimSpace(cur.String()))
			cur.Reset()
		default:
			cur.WriteRune(r)
		}
	}
	return append(parts, strings.TrimSpace(cur.String()))
}

// depthOf counts the unclosed brackets and braces of a value (outside strings).
func depthOf(s string) int {
	depth := 0
	var quote rune
	for i, r := range s {
		switch {
		case quote != 0:
			if r == quote && (i == 0 || s[i-1] != '\\' || quote == '\'') {
				quote = 0
			}
		case r == '"' || r == '\'':
			quote = r
		case r == '[' || r == '{':
			depth++
		case r == ']' || r == '}':
			depth--
		}
	}
	return depth
}

// parseTOMLValue parses one value and returns it with the unparsed rest of the input.
func parseTOMLValue(s string) (any, string) {
	s = strings.TrimLeftFunc(s, unicode.IsSpace)
	if s == "" {
		return "", ""
	}
	switch s[0] {
	case '"', '\'':
		q := s[0]
		var b strings.Builder
		for i := 1; i < len(s); i++ {
			switch {
			case s[i] == '\\' && q == '"' && i+1 < len(s):
				i++
				switch s[i] {
				case 'n':
					b.WriteByte('\n')
				case 't':
					b.WriteByte('\t')
				default:
					b.WriteByte(s[i])
				}
			case s[i] == q:
				return b.String(), s[i+1:]
			default:
				b.WriteByte(s[i])
			}
		}
		return b.String(), ""
	case '[':
		var list []any
		rest := s[1:]
		for {
			rest = strings.TrimLeft(rest, " \t,")
			if rest == "" || rest[0] == ']' {
				if rest != "" {
					rest = rest[1:]
				}
				return list, rest
			}
			var v any
			v, rest = parseTOMLValue(rest)
			list = append(list, v)
		}
	case '{':
		m := map[string]any{}
		rest := s[1:]
		for {
			rest = strings.TrimLeft(rest, " \t,")
			if rest == "" || rest[0] == '}' {
				if rest != "" {
					rest = rest[1:]
				}
				return m, rest
			}
			eq := strings.IndexByte(rest, '=')
			if eq < 0 {
				return m, ""
			}
			key := strings.Join(splitTOMLKey(strings.TrimSpace(rest[:eq])), ".")
			var v any
			v, rest = parseTOMLValue(rest[eq+1:])
			m[key] = v
		}
	}
	end := strings.IndexAny(s, ",]}")
	if end < 0 {
		end = len(s)
	}
	return strings.TrimSpace(s[:end]), s[end:]
}
