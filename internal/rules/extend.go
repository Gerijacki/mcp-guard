package rules

import (
	"fmt"
	"regexp"
	"strings"
)

// Extension is a user's addition to a built-in taint rule: extra operations that must not
// receive tool input (Sinks) and expressions that make a value safe (Sanitizers). It comes
// from the "extend" section of .mcp-guard.yaml.
type Extension struct {
	Sinks      []string
	Sanitizers []string
}

// extension is an Extension with its regular expressions compiled.
type extension struct {
	sinks      *regexp.Regexp // alternation of the extra sinks, nil if none
	sanitizers *regexp.Regexp // alternation of the extra sanitizers, nil if none
}

func (e extension) withSanitizers(base *regexp.Regexp) *regexp.Regexp {
	if e.sanitizers == nil {
		return base
	}
	return regexp.MustCompile("(?:" + base.String() + ")|" + e.sanitizers.String())
}

// supportsSinks lists the rules whose extra sinks are understood; MCPG012 only takes sanitizers.
var extendable = map[string]bool{"MCPG001": true, "MCPG004": true, "MCPG005": true, "MCPG009": true, "MCPG010": true, "MCPG012": true}

func compileExtension(id string, e Extension) (extension, error) {
	var out extension
	join := func(what string, pats []string, mustCall bool) (*regexp.Regexp, error) {
		if len(pats) == 0 {
			return nil, nil
		}
		for _, p := range pats {
			if _, err := regexp.Compile(p); err != nil {
				return nil, fmt.Errorf("extend %s: %s %q: %w", id, what, p, err)
			}
			if mustCall && !strings.HasSuffix(p, `(`) {
				return nil, fmt.Errorf(`extend %s: sink %q must end at the opening parenthesis of the call, e.g. '\bstorage\.read\s*\('`, id, p)
			}
		}
		return regexp.Compile("(?:" + strings.Join(pats, ")|(?:") + ")")
	}
	var err error
	if out.sinks, err = join("sink", e.Sinks, true); err != nil {
		return out, err
	}
	if out.sanitizers, err = join("sanitizer", e.Sanitizers, false); err != nil {
		return out, err
	}
	return out, nil
}

// WithExtensions returns rs with the extensions applied to the matching built-in rules.
func WithExtensions(rs []Rule, ext map[string]Extension) ([]Rule, error) {
	for id, e := range ext {
		if !extendable[id] {
			return nil, fmt.Errorf("extend: %s cannot be extended (supported: MCPG001, MCPG004, MCPG005, MCPG009, MCPG010, MCPG012)", id)
		}
		if id == "MCPG012" && len(e.Sinks) > 0 {
			return nil, fmt.Errorf("extend MCPG012: sinks are not supported (it recognizes CLIs by name); use sanitizers")
		}
	}
	out := make([]Rule, len(rs))
	copy(out, rs)
	for i, r := range out {
		id := r.Meta().ID
		e, ok := ext[id]
		if !ok {
			continue
		}
		x, err := compileExtension(id, e)
		if err != nil {
			return nil, err
		}
		switch rr := r.(type) {
		case fileAccessRule:
			rr.ext = x
			out[i] = rr
		case commandInjectionRule:
			rr.ext = x
			out[i] = rr
		case sqlInjectionRule:
			rr.ext = x
			out[i] = rr
		case ssrfRule:
			rr.ext = x
			out[i] = rr
		case deserializationRule:
			rr.ext = x
			out[i] = rr
		case argInjectionRule:
			rr.ext = x
			out[i] = rr
		}
	}
	return out, nil
}
