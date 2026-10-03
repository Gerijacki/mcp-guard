package extract

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/Gerijacki/mcp-guard/internal/source"
)

var update = flag.Bool("update", false, "rewrite the golden files")

// The golden files pin the complete extraction result (names, parameters, descriptions,
// annotations, body line ranges, helper functions, client-config servers) of every file in
// testdata/extract, so a change in the extractors shows up as a readable diff instead of as a
// change in findings somewhere downstream.

type goldenTool struct {
	Name        string            `json:"name"`
	Kind        string            `json:"kind,omitempty"`
	Line        int               `json:"line"`
	Params      []string          `json:"params"`
	Description string            `json:"description,omitempty"`
	ParamDescs  []string          `json:"param_descriptions,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
	Body        [2]int            `json:"body_lines"`
	Dispatcher  bool              `json:"dispatcher,omitempty"`
}

type goldenFile struct {
	Tools   []goldenTool          `json:"tools,omitempty"`
	Funcs   []string              `json:"functions,omitempty"`
	Servers []source.ConfigServer `json:"servers,omitempty"`
}

func snapshot(f *source.File) goldenFile {
	var g goldenFile
	for _, t := range f.Tools {
		params := t.Params
		if params == nil {
			params = []string{}
		}
		g.Tools = append(g.Tools, goldenTool{
			Name: t.Name, Kind: t.Kind, Line: t.Line, Params: params, Description: t.Description,
			ParamDescs: t.ParamDescriptions, Annotations: t.Annotations, Body: [2]int{t.BodyStart, t.BodyEnd}, Dispatcher: t.Dispatcher,
		})
	}
	for _, fn := range f.Funcs {
		g.Funcs = append(g.Funcs, fn.Name+"("+strings.Join(fn.Params, ",")+")")
	}
	sort.Strings(g.Funcs)
	g.Servers = f.Servers
	return g
}

func TestExtractionGolden(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("..", "..", "testdata", "extract", "*"))
	if err != nil || len(files) == 0 {
		t.Fatal("no extraction fixtures", err)
	}
	for _, path := range files {
		if info, err := os.Stat(path); err != nil || info.IsDir() || source.DetectLanguage(path) == source.Unknown {
			continue
		}
		name := filepath.Base(path)
		t.Run(name, func(t *testing.T) {
			f := load(t, name)
			got, err := json.MarshalIndent(snapshot(f), "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			goldenPath := filepath.Join("testdata", name+".golden.json")
			if *update {
				if err := os.MkdirAll("testdata", 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(goldenPath, append(got, '\n'), 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(goldenPath)
			if err != nil {
				t.Fatalf("%v (run: go test ./internal/extract -update)", err)
			}
			if strings.TrimSpace(strings.ReplaceAll(string(want), "\r\n", "\n")) != strings.TrimSpace(string(got)) {
				t.Errorf("extraction of %s changed; if intended run: go test ./internal/extract -update\n--- got ---\n%s", name, got)
			}
		})
	}
}
