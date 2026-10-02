// Package lock records a fingerprint of every MCP tool definition and client-config server in
// a project, so that later scans can tell when one changed (a "rug pull": a description or
// launch command that was reviewed once and silently changed afterwards).
//
// The lock holds hashes of what the model reads (name, description, parameter descriptions,
// parameter names, annotations) and of how a server is launched (command, args, URL). Handler
// code is not part of it: implementation changes are ordinary code review.
package lock

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Gerijacki/mcp-guard/internal/source"
)

// DefaultName is the conventional lock file name.
const DefaultName = "mcp-guard.lock"

const version = 1

// File is the on-disk lock.
type File struct {
	Version int     `json:"version"`
	Tools   []Entry `json:"tools"`
	Servers []Entry `json:"servers"`
}

// Entry fingerprints one tool (or resource, prompt) or one client-config server.
type Entry struct {
	Key  string `json:"key"`  // path relative to the scan root + "#" + name
	Kind string `json:"kind"` // tool, resource, prompt or server
	// Description is kept (shortened) so a reviewer can see what was approved.
	Description string `json:"description,omitempty"`
	Text        string `json:"text_hash"`  // name, description and parameter descriptions
	Shape       string `json:"shape_hash"` // parameter names and annotations (tools) or command, args, URL (servers)
}

// Source is the extracted content of one scanned file.
type Source struct {
	Path    string
	Tools   []source.Tool
	Servers []source.ConfigServer
}

// RelPath returns p relative to root, slash-separated (the key used in the lock).
func RelPath(root, p string) string {
	if info, err := os.Stat(root); err == nil && !info.IsDir() {
		return path.Base(filepath.ToSlash(p))
	}
	if rel, err := filepath.Rel(root, p); err == nil {
		return filepath.ToSlash(rel)
	}
	return filepath.ToSlash(p)
}

func sum(parts ...string) string {
	h := sha256.New()
	for _, p := range parts {
		fmt.Fprintf(h, "%d:%s|", len(p), p)
	}
	return hex.EncodeToString(h.Sum(nil))[:32]
}

// ToolEntry builds the entry of a tool found in the file at relPath.
func ToolEntry(relPath string, t source.Tool) Entry {
	kind := t.Kind
	if kind == "" {
		kind = "tool"
	}
	ann := make([]string, 0, len(t.Annotations))
	for k, v := range t.Annotations {
		ann = append(ann, k+"="+v)
	}
	sort.Strings(ann)
	params := append([]string(nil), t.Params...)
	sort.Strings(params)
	return Entry{
		Key:         relPath + "#" + t.Name,
		Kind:        kind,
		Description: shorten(t.Description),
		Text:        sum(t.Name, t.Description, strings.Join(t.ParamDescriptions, "\x00")),
		Shape:       sum(strings.Join(params, ","), strings.Join(ann, ",")),
	}
}

// ServerEntry builds the entry of a client-config server. Environment variables and headers
// are left out: they hold secrets and change per machine.
func ServerEntry(relPath string, s source.ConfigServer) Entry {
	return Entry{
		Key:   relPath + "#" + s.Name,
		Kind:  "server",
		Text:  sum(s.Name),
		Shape: sum(s.Command, strings.Join(s.Args, "\x00"), s.URL),
	}
}

func shorten(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if r := []rune(s); len(r) > 200 {
		return string(r[:200]) + "…"
	}
	return s
}

// Build creates a lock from the extracted content of all files; paths are made relative to root.
func Build(root string, files []Source) *File {
	l := &File{Version: version, Tools: []Entry{}, Servers: []Entry{}}
	for _, f := range files {
		rel := RelPath(root, f.Path)
		for _, t := range f.Tools {
			l.Tools = append(l.Tools, ToolEntry(rel, t))
		}
		for _, s := range f.Servers {
			l.Servers = append(l.Servers, ServerEntry(rel, s))
		}
	}
	sort.Slice(l.Tools, func(i, j int) bool { return l.Tools[i].Key < l.Tools[j].Key })
	sort.Slice(l.Servers, func(i, j int) bool { return l.Servers[i].Key < l.Servers[j].Key })
	return l
}

// Save writes the lock as indented JSON.
func (l *File) Save(p string) error {
	b, err := json.MarshalIndent(l, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(p, append(b, '\n'), 0o644)
}

// Load reads a lock file.
func Load(p string) (*File, error) {
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	var l File
	if err := json.Unmarshal(b, &l); err != nil {
		return nil, fmt.Errorf("%s: %w", p, err)
	}
	if l.Version != version {
		return nil, fmt.Errorf("%s: unsupported lock version %d (want %d)", p, l.Version, version)
	}
	return &l, nil
}

// Change says how an entry differs from the lock.
type Change int

const (
	Unchanged    Change = iota
	New                 // not in the lock
	TextChanged         // description / parameter descriptions (or name) differ
	ShapeChanged        // parameters, annotations or launch command differ
)

// Compare looks e up in the lock and reports what changed, and the locked description.
func (l *File) Compare(e Entry) (Change, Entry) {
	list := l.Tools
	if e.Kind == "server" {
		list = l.Servers
	}
	i := sort.Search(len(list), func(i int) bool { return list[i].Key >= e.Key })
	if i == len(list) || list[i].Key != e.Key {
		return New, Entry{}
	}
	old := list[i]
	switch {
	case old.Text != e.Text:
		return TextChanged, old
	case old.Shape != e.Shape:
		return ShapeChanged, old
	}
	return Unchanged, old
}
