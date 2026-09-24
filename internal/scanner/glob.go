package scanner

import (
	"regexp"
	"strings"
	"sync"
)

var globCache sync.Map // pattern -> *regexp.Regexp

// matchAny reports whether a slash-separated relative path matches any glob pattern.
//
// Supported syntax: "*" (any run of characters except '/'), "**" (any number of path
// segments), "?" (one character). A pattern without '/' matches a file or directory
// name at any depth ("node_modules", "*.test.ts"); a pattern matching a directory also
// matches everything inside it.
func matchAny(patterns []string, rel string) bool {
	for _, p := range patterns {
		if matchGlob(p, rel) {
			return true
		}
	}
	return false
}

func matchGlob(pattern, rel string) bool {
	pattern = strings.TrimPrefix(strings.TrimSpace(pattern), "./")
	if pattern == "" {
		return false
	}
	re := globRegexp(pattern)
	if re.MatchString(rel) {
		return true
	}
	// A directory pattern also covers its contents.
	for i := strings.IndexByte(rel, '/'); i >= 0; {
		if re.MatchString(rel[:i]) {
			return true
		}
		next := strings.IndexByte(rel[i+1:], '/')
		if next < 0 {
			break
		}
		i += next + 1
	}
	return false
}

func globRegexp(pattern string) *regexp.Regexp {
	if re, ok := globCache.Load(pattern); ok {
		return re.(*regexp.Regexp)
	}
	anchored := strings.Contains(strings.TrimSuffix(pattern, "/"), "/")
	p := strings.TrimSuffix(strings.TrimPrefix(pattern, "/"), "/")
	var b strings.Builder
	if !anchored {
		b.WriteString(`^(?:.*/)?`)
	} else {
		b.WriteString(`^`)
	}
	for i := 0; i < len(p); i++ {
		c := p[i]
		switch {
		case c == '*' && i+1 < len(p) && p[i+1] == '*':
			i++
			if i+1 < len(p) && p[i+1] == '/' {
				i++
				b.WriteString(`(?:.*/)?`)
			} else {
				b.WriteString(`.*`)
			}
		case c == '*':
			b.WriteString(`[^/]*`)
		case c == '?':
			b.WriteString(`[^/]`)
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	b.WriteString(`$`)
	re := regexp.MustCompile(b.String())
	globCache.Store(pattern, re)
	return re
}
