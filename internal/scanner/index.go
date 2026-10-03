package scanner

import (
	"path"
	"strings"

	"github.com/Gerijacki/mcp-guard/internal/source"
)

// index maps function names to their definitions across all scanned code files, so that a
// tool calling a helper from another module can be followed into it.
//
// A call is only resolved when it is unambiguous: exactly one definition of the name exists
// in the whole scan, and the calling file shows it knows the other file (an import naming the
// module for Python and TypeScript, the same directory for Go packages).
type index struct {
	byName map[string][]entry
}

type entry struct {
	f  *source.File
	fn source.Func
}

func buildIndex(files []*source.File) *index {
	ix := &index{byName: map[string][]entry{}}
	for _, f := range files {
		if !f.Language.IsCode() {
			continue
		}
		handlers := map[[2]int]bool{}
		for _, t := range f.Tools {
			handlers[[2]int{t.BodyFrom, t.BodyTo}] = true
		}
		for _, fn := range f.Funcs {
			if handlers[[2]int{fn.BodyFrom, fn.BodyTo}] {
				continue // an MCP handler is analyzed as a tool already
			}
			k := key(f.Language, fn.Name)
			ix.byName[k] = append(ix.byName[k], entry{f, fn})
		}
	}
	return ix
}

func key(lang source.Language, name string) string { return string(lang) + "|" + name }

// resolve implements rules.Resolver.
func (ix *index) resolve(from *source.File, name string) (*source.File, source.Func, bool) {
	defs := ix.byName[key(from.Language, name)]
	if len(defs) != 1 || defs[0].f == from {
		return nil, source.Func{}, false
	}
	e := defs[0]
	if !related(from, e.f) {
		return nil, source.Func{}, false
	}
	return e.f, e.fn, true
}

// related reports whether from plausibly imports to.
func related(from, to *source.File) bool {
	if from.Language == source.Go {
		return path.Dir(from.Path) == path.Dir(to.Path) // same package directory
	}
	base := strings.TrimSuffix(path.Base(to.Path), path.Ext(to.Path))
	if base == "__init__" || base == "index" {
		base = path.Base(path.Dir(to.Path))
	}
	return base != "" && base != "." && strings.Contains(from.Content, base)
}
