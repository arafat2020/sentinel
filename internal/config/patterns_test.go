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

	for _, p := range loaded {
		for _, pp := range p.Processes {
			if pp.Ordered {
				t.Errorf("pattern %q process %q became ordered; existing files must stay unordered", p.Name, pp.ID)
			}
		}
	}
}

// The on-disk format for existing patterns must not change: saving the
// defaults reproduces the shipped file byte for byte.
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
	if bytes.Contains(got, []byte("ordered")) {
		t.Fatal("unordered patterns must not gain an ordered key")
	}
}

func TestOrderedFlagRoundTrips(t *testing.T) {
	path := writeFile(t, `patterns:
    - name: dns-then-connect
      severity: HIGH
      title: Lookup then connect
      description: test
      processes:
        - id: parent
          events: []
        - id: child
          ordered: true
          events:
            - type: DNS_QUERY
            - type: NETWORK_CONNECT
      relationships:
        - type: SPAWNED
          parent: parent
          child: child
`)

	loaded, err := LoadPatterns(path)
	if err != nil {
		t.Fatalf("LoadPatterns: %v", err)
	}
	if len(loaded) != 1 || len(loaded[0].Processes) != 2 {
		t.Fatalf("unexpected patterns: %+v", loaded)
	}
	if loaded[0].Processes[0].Ordered {
		t.Error("a process without the key must be unordered")
	}
	child := loaded[0].Processes[1]
	if !child.Ordered {
		t.Error("ordered: true was not loaded")
	}
	if len(child.Events) != 2 || child.Events[0].Type != core.EventDNSQuery || child.Events[1].Type != core.EventNetworkConnect {
		t.Errorf("event order not preserved: %+v", child.Events)
	}

	saved := filepath.Join(t.TempDir(), "saved.yaml")
	if err := SavePatterns(saved, loaded); err != nil {
		t.Fatalf("SavePatterns: %v", err)
	}
	data, _ := os.ReadFile(saved)
	if got := strings.Count(string(data), "ordered: true"); got != 1 {
		t.Errorf("saved file has %d ordered keys, want 1:\n%s", got, data)
	}

	reloaded, err := LoadPatterns(saved)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if !reflect.DeepEqual(normalize(reloaded), normalize(loaded)) {
		t.Errorf("round trip changed the patterns:\n%+v\n%+v", loaded, reloaded)
	}
}

// The shipped file, loaded through the config layer, still detects the
// behaviour it describes.
func TestShippedPatternStillDetectsItsBehaviour(t *testing.T) {
	loaded, err := LoadPatterns(shippedPatterns)
	if err != nil {
		t.Fatalf("LoadPatterns: %v", err)
	}

	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	parent := core.Process{PID: 100, Name: "node", StartTime: base.Add(-time.Hour)}
	child := core.Process{PID: 200, PPID: 100, Name: "python", StartTime: base}

	engine := correlation.NewEngine(5 * time.Minute)
	engine.SetPatterns(loaded)

	feed := func(eventType core.EventType, p core.Process, offset time.Duration) {
		ts := base.Add(offset)
		engine.ProcessAt(core.Event{Type: eventType, Timestamp: ts, Process: &p}, ts)
	}
	feed(core.EventProcessStart, parent, 0)
	feed(core.EventNetworkConnect, parent, time.Second)
	feed(core.EventProcessStart, child, 2*time.Second)
	feed(core.EventNetworkConnect, child, 3*time.Second)

	findings := engine.DetectBehaviorsAt(base.Add(4 * time.Second))
	if len(findings) != 1 || findings[0].Rule != "network-active-parent-spawns-python" {
		t.Fatalf("findings = %+v", findings)
	}
	if findings[0].Severity != core.SeverityMedium {
		t.Errorf("severity = %s, want MEDIUM", findings[0].Severity)
	}
}

func TestLoadPatternsStillRejectsInvalidFiles(t *testing.T) {
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
		"unknown relationship": `patterns:
    - name: x
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
