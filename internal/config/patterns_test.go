package config

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/arafat2020/sentinel/internal/core"
	"github.com/arafat2020/sentinel/internal/detection/correlation"
)

const shippedPatterns = "../../configs/patterns.yaml"

// normalize makes nil and empty slices compare equal: YAML loading produces
// empty slices where hand-written patterns leave them nil.
func normalize(patterns []correlation.BehaviorPattern) []correlation.BehaviorPattern {
	out := make([]correlation.BehaviorPattern, len(patterns))
	for i, p := range patterns {
		p.Processes = append([]correlation.ProcessPattern{}, p.Processes...)
		for j, pp := range p.Processes {
			pp.Conditions = append([]correlation.Condition{}, pp.Conditions...)
			pp.Events = append([]correlation.EventPattern{}, pp.Events...)
			p.Processes[j] = pp
		}
		p.Relationships = append([]correlation.RelationshipPattern{}, p.Relationships...)
		out[i] = p
	}
	return out
}

func writeFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "patterns.yaml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestShippedPatternsFileLoadsAsDefaults(t *testing.T) {
	loaded, err := LoadPatterns(shippedPatterns)
	if err != nil {
		t.Fatalf("LoadPatterns: %v", err)
	}

	if !reflect.DeepEqual(normalize(loaded), normalize(correlation.DefaultPatterns())) {
		t.Fatalf("shipped patterns differ from DefaultPatterns:\n%+v", loaded)
	}
}

// The YAML schema is unchanged: saving the defaults reproduces the shipped
// file byte for byte.
func TestSavingDefaultsReproducesShippedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "patterns.yaml")
	if err := SavePatterns(path, correlation.DefaultPatterns()); err != nil {
		t.Fatalf("SavePatterns: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(shippedPatterns)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(got, want) {
		t.Fatalf("saved defaults differ from %s:\n%s", shippedPatterns, got)
	}
}

// The shipped file, loaded through the config layer, still detects the
// behaviour it describes.
func TestShippedPatternStillDetectsItsBehaviour(t *testing.T) {
	loaded, err := LoadPatterns(shippedPatterns)
	if err != nil {
		t.Fatalf("LoadPatterns: %v", err)
	}

	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	parent := core.Process{PID: 100, Name: "node", StartTime: now.Add(-time.Hour)}
	child := core.Process{PID: 200, PPID: 100, Name: "python", StartTime: now}

	engine := correlation.NewEngine(5*time.Minute, correlation.WithClock(func() time.Time { return now }))
	engine.SetPatterns(loaded)

	for _, event := range []core.Event{
		{Type: core.EventProcessStart, Process: &parent},
		{Type: core.EventNetworkConnect, Process: &parent},
		{Type: core.EventProcessStart, Process: &child},
		{Type: core.EventNetworkConnect, Process: &child},
	} {
		now = now.Add(time.Second)
		event.Timestamp = now
		engine.Process(event)
	}

	findings := engine.DetectBehaviors()
	if len(findings) != 1 || findings[0].Rule != "network-active-parent-spawns-python" {
		t.Fatalf("findings = %+v", findings)
	}
	if findings[0].Severity != core.SeverityMedium {
		t.Errorf("severity = %s, want MEDIUM", findings[0].Severity)
	}
}

func TestMultiRelationshipPatternLoads(t *testing.T) {
	loaded, err := LoadPatterns(writeFile(t, `patterns:
    - name: chain
      severity: HIGH
      processes:
        - id: a
        - id: b
        - id: c
      relationships:
        - type: SPAWNED
          parent: a
          child: b
        - type: SPAWNED
          parent: b
          child: c
    - name: lone-process
      severity: LOW
      processes:
        - id: only
          events:
            - type: DNS_QUERY
`))
	if err != nil {
		t.Fatalf("LoadPatterns: %v", err)
	}
	if len(loaded) != 2 || len(loaded[0].Relationships) != 2 || len(loaded[1].Processes) != 1 {
		t.Fatalf("unexpected patterns: %+v", loaded)
	}
}

func TestLoadPatternsRejectsStructurallyInvalidPatterns(t *testing.T) {
	cases := map[string]struct {
		yaml string
		want string // the error must say what is wrong, and where
	}{
		"two roles and no relationships": {`patterns:
    - name: unrelated
      processes:
        - id: a
        - id: b
`, "no relationships"},
		"relationship with unknown parent role": {`patterns:
    - name: ghost-parent
      processes:
        - id: a
        - id: b
      relationships:
        - type: SPAWNED
          parent: ghost
          child: b
`, `unknown role "ghost"`},
		"relationship with unknown child role": {`patterns:
    - name: ghost-child
      processes:
        - id: a
        - id: b
      relationships:
        - type: SPAWNED
          parent: a
          child: ghost
`, `unknown role "ghost"`},
		"duplicate role ids": {`patterns:
    - name: twins
      processes:
        - id: a
        - id: a
      relationships:
        - type: SPAWNED
          parent: a
          child: a
`, `duplicate role id "a"`},
		"role outside every relationship": {`patterns:
    - name: bystander
      processes:
        - id: a
        - id: b
        - id: c
      relationships:
        - type: SPAWNED
          parent: a
          child: b
`, `role "c" is not part of any relationship`},
	}

	for name, c := range cases {
		_, err := LoadPatterns(writeFile(t, c.yaml))
		if err == nil {
			t.Errorf("%s: expected an error", name)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: error %q does not mention %q", name, err, c.want)
		}
		if !strings.Contains(err.Error(), "pattern[0]") {
			t.Errorf("%s: error %q does not identify the pattern", name, err)
		}
	}
}

func TestLoadPatternsStillRejectsMalformedFiles(t *testing.T) {
	cases := map[string]string{
		"missing name": `patterns:
    - severity: LOW
`,
		"unknown condition": `patterns:
    - name: x
      processes:
        - id: p
          conditions:
            - type: PROCESS_COLOR
              value: blue
`,
		"unknown relationship type": `patterns:
    - name: x
      processes:
        - id: a
        - id: b
      relationships:
        - type: ADOPTED
          parent: a
          child: b
`,
		"malformed yaml": "patterns: [",
	}

	for name, content := range cases {
		if _, err := LoadPatterns(writeFile(t, content)); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

// A pattern freshly created in the editor has no roles yet. It must stay
// loadable, or one unfinished draft would discard every saved pattern.
func TestDraftPatternWithoutRolesStillLoads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "patterns.yaml")
	draft := correlation.BehaviorPattern{Name: "new-pattern", Severity: core.SeverityMedium, Title: "New Pattern"}

	if err := SavePatterns(path, append(correlation.DefaultPatterns(), draft)); err != nil {
		t.Fatalf("SavePatterns: %v", err)
	}
	loaded, err := LoadPatterns(path)
	if err != nil {
		t.Fatalf("LoadPatterns: %v", err)
	}
	if len(loaded) != 2 {
		t.Fatalf("loaded %d patterns, want 2", len(loaded))
	}
}
