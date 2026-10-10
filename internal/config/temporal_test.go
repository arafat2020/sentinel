package config

import (
	"bytes"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/arafat2020/sentinel/internal/core"
	"github.com/arafat2020/sentinel/internal/detection/correlation"
)

const v3Patterns = "testdata/patterns_v3.yaml"

func TestV3FileParses(t *testing.T) {
	loaded := mustLoad(t, v3Patterns)
	if len(loaded.Patterns) != 2 {
		t.Fatalf("loaded %d patterns, want 2", len(loaded.Patterns))
	}

	pattern := loaded.Patterns[0]

	deep := pattern.Relationships[0]
	if deep.Type != correlation.RelationshipDescendant || deep.MaxDepth != 4 {
		t.Errorf("first relationship = %+v, want DESCENDANT with max_depth 4", deep)
	}
	if direct := pattern.Relationships[1]; direct.Type != correlation.RelationshipSpawned || direct.MaxDepth != 0 {
		t.Errorf("second relationship = %+v, want SPAWNED", direct)
	}

	lookups := pattern.Processes[1].Events[0]
	if lookups.Count != 20 || lookups.Within != time.Minute || lookups.Distinct != "domain" || lookups.Where == nil {
		t.Errorf("threshold = %+v, want count 20 within 60s distinct domain with a where", lookups)
	}
	if connects := pattern.Processes[1].Events[1]; connects.Count != 3 || connects.Within != 0 || connects.Distinct != "" {
		t.Errorf("count-only threshold = %+v", connects)
	}

	sequence := pattern.Sequence
	if sequence == nil || sequence.Within != 30*time.Second || len(sequence.Steps) != 3 {
		t.Fatalf("sequence = %+v", sequence)
	}
	// 0s is a tolerance of none, not the default.
	if sequence.OrderTolerance == nil || *sequence.OrderTolerance != 0 {
		t.Errorf("order_tolerance = %v, want an explicit 0", sequence.OrderTolerance)
	}
	if created := sequence.Steps[1]; created.Capture != "dropped" || created.Type != core.EventFileCreate || created.Where == nil {
		t.Errorf("capturing step = %+v", created)
	}
	reference := sequence.Steps[2].Where.Fields[0].Predicate
	if reference.Eq == nil || *reference.Eq != "$dropped.path" || !reference.NoCase {
		t.Errorf("referencing predicate = %+v", reference)
	}

	// Left out means the defaults, and stays left out.
	defaults := loaded.Patterns[1]
	if defaults.Relationships[0].MaxDepth != 0 || defaults.Sequence.OrderTolerance != nil || defaults.Sequence.Within != 0 {
		t.Errorf("defaults were filled in on load: %+v / %+v", defaults.Relationships[0], defaults.Sequence)
	}

	for _, p := range loaded.Patterns {
		if !p.UsesAdvancedFields() {
			t.Errorf("pattern %q should be marked as using advanced fields", p.Name)
		}
	}
}

func TestV3FileRoundTrips(t *testing.T) {
	original := mustLoad(t, v3Patterns)
	path := copyFile(t, v3Patterns)

	var previous []byte
	for pass := 0; pass < 2; pass++ {
		if err := SavePatterns(path, mustLoad(t, path).Patterns); err != nil {
			t.Fatal(err)
		}

		reloaded := mustLoad(t, path)
		if !reflect.DeepEqual(reloaded, original) {
			t.Fatalf("pass %d: the file changed meaning when saved:\n%+v\n%+v", pass, original, reloaded)
		}

		data, _ := os.ReadFile(path)
		if pass > 0 && !bytes.Equal(data, previous) {
			t.Fatalf("saving a saved file changed it:\n%s", data)
		}
		previous = data
	}

	saved := string(previous)
	for _, want := range []string{
		"type: DESCENDANT", "max_depth: 4",
		"count: 20", "within: 60s", "distinct: domain",
		"within: 30s", "order_tolerance: 0s", "capture: dropped",
		"{eq: $dropped.path, nocase: true}",
	} {
		if !strings.Contains(saved, want) {
			t.Errorf("saved file does not contain %q:\n%s", want, saved)
		}
	}

	// Defaults that were not written are not written back.
	if strings.Count(saved, "max_depth") != 1 || strings.Count(saved, "order_tolerance") != 1 {
		t.Errorf("defaults were written out:\n%s", saved)
	}
}

func TestDurationsAreWrittenReadably(t *testing.T) {
	for d, want := range map[time.Duration]string{
		0:                      "",
		500 * time.Millisecond: "500ms",
		30 * time.Second:       "30s",
		60 * time.Second:       "60s",
		90 * time.Second:       "90s",
		2 * time.Minute:        "2m",
		150 * time.Second:      "2m30s",
		5 * time.Minute:        "5m",
		time.Hour:              "1h",
		90 * time.Minute:       "90m",
	} {
		got := formatDuration(d)
		if got != want {
			t.Errorf("formatDuration(%v) = %q, want %q", d, got, want)
		}
		if back, err := parseDuration(got); err != nil || back != d {
			t.Errorf("parseDuration(%q) = %v, %v; want %v", got, back, err, d)
		}
	}
}

// temporal wraps a pattern body in a file with two related roles.
func temporal(body string) string {
	return `patterns:
    - name: bad
      processes:
        - id: dropper
        - id: payload
      relationships:
        - {type: SPAWNED, parent: dropper, child: payload}
` + body
}

func TestLoadPatternsReportsTemporalErrors(t *testing.T) {
	cases := map[string]struct {
		yaml string
		want []string
	}{
		"max_depth out of range": {
			"patterns:\n    - name: bad\n      processes:\n        - id: a\n        - id: b\n      relationships:\n        - {type: DESCENDANT, parent: a, child: b, max_depth: 17}\n",
			[]string{"relationships[0]", "max_depth must be between 1 and 16, got 17"},
		},
		"max_depth on SPAWNED": {
			"patterns:\n    - name: bad\n      processes:\n        - id: a\n        - id: b\n      relationships:\n        - {type: SPAWNED, parent: a, child: b, max_depth: 2}\n",
			[]string{"relationships[0]", "max_depth applies to DESCENDANT"},
		},
		"count below one": {
			"patterns:\n    - name: bad\n      processes:\n        - id: a\n          events:\n            - {type: DNS_QUERY, count: -2}\n",
			[]string{`role "a"`, "events[0] (DNS_QUERY)", "count must be at least 1"},
		},
		"within longer than the window": {
			"patterns:\n    - name: bad\n      processes:\n        - id: a\n          events:\n            - {type: DNS_QUERY, count: 5, within: 10m}\n",
			[]string{`role "a"`, "events[0] (DNS_QUERY)", "at most the correlation window (5m0s), got 10m0s"},
		},
		"within that is not a duration": {
			"patterns:\n    - name: bad\n      processes:\n        - id: a\n          events:\n            - {type: DNS_QUERY, count: 5, within: sixty}\n",
			[]string{`role "a"`, "events[0] (DNS_QUERY)", `within: "sixty" is not a duration`},
		},
		"within of zero": {
			"patterns:\n    - name: bad\n      processes:\n        - id: a\n          events:\n            - {type: DNS_QUERY, count: 5, within: 0s}\n",
			[]string{"events[0] (DNS_QUERY)", "within: must be more than 0"},
		},
		"within without count or distinct": {
			"patterns:\n    - name: bad\n      processes:\n        - id: a\n          events:\n            - {type: DNS_QUERY, within: 60s}\n",
			[]string{"events[0] (DNS_QUERY)", "within needs a count above 1 or distinct"},
		},
		"distinct field of another event type": {
			"patterns:\n    - name: bad\n      processes:\n        - id: a\n          events:\n            - {type: DNS_QUERY, count: 5, distinct: remote_port}\n",
			[]string{"events[0] (DNS_QUERY)", `distinct: "remote_port" is not a field of DNS_QUERY events`},
		},
		"unknown capture": {
			temporal("      sequence:\n        steps:\n          - {role: dropper, type: FILE_CREATE, capture: dropped}\n          - role: payload\n            type: PROCESS_START\n            where:\n              exe: {eq: $missing.path}\n"),
			[]string{"sequence: steps[1] (PROCESS_START)", "where.exe", "reference $missing.path", `unknown capture "missing"`},
		},
		"capture defined after use": {
			temporal("      sequence:\n        steps:\n          - role: payload\n            type: PROCESS_START\n            where:\n              exe: {eq: $dropped.path}\n          - {role: dropper, type: FILE_CREATE, capture: dropped}\n"),
			[]string{"sequence: steps[0] (PROCESS_START)", "reference $dropped.path", "defined by steps[1], after this step"},
		},
		"invalid captured field": {
			temporal("      sequence:\n        steps:\n          - {role: dropper, type: FILE_CREATE, capture: dropped}\n          - role: payload\n            type: PROCESS_START\n            where:\n              exe: {eq: $dropped.domain}\n"),
			[]string{"sequence: steps[1] (PROCESS_START)", "reference $dropped.domain", "is not a field of the captured FILE_CREATE event"},
		},
		"kind mismatch": {
			temporal("      sequence:\n        steps:\n          - {role: dropper, type: NETWORK_CONNECT, capture: conn}\n          - role: payload\n            type: PROCESS_START\n            where:\n              exe: {eq: $conn.remote_port}\n"),
			[]string{"sequence: steps[1] (PROCESS_START)", "reference $conn.remote_port", "a string field cannot be compared with a numeric field"},
		},
		"duplicate capture": {
			temporal("      sequence:\n        steps:\n          - {role: dropper, type: FILE_CREATE, capture: f}\n          - {role: dropper, type: FILE_MODIFY, capture: f}\n"),
			[]string{"sequence: steps[1]", `capture "f" is already defined by steps[0]`},
		},
		"step with an unknown role": {
			temporal("      sequence:\n        steps:\n          - {role: ghost, type: DNS_QUERY}\n"),
			[]string{"sequence: steps[0]", `unknown role "ghost"`},
		},
		"sequence within longer than the window": {
			temporal("      sequence:\n        within: 1h\n        steps:\n          - {role: dropper, type: DNS_QUERY}\n"),
			[]string{"sequence: within", "at most the correlation window (5m0s)"},
		},
		"order_tolerance that is not a duration": {
			temporal("      sequence:\n        order_tolerance: soon\n        steps:\n          - {role: dropper, type: DNS_QUERY}\n"),
			[]string{"sequence: order_tolerance", `"soon" is not a duration`},
		},
		"sequence without steps": {
			temporal("      sequence:\n        within: 10s\n"),
			[]string{"sequence: steps", "at least one step"},
		},
	}

	for name, c := range cases {
		set, err := LoadPatterns(writeFile(t, c.yaml))
		if err != nil {
			t.Errorf("%s: the whole file was rejected: %v", name, err)
			continue
		}
		if len(set.Patterns) != 0 || len(set.Errors) != 1 {
			t.Errorf("%s: loaded %d patterns with %d errors, want 0 and 1", name, len(set.Patterns), len(set.Errors))
			continue
		}

		message := set.Errors[0].Error()
		for _, want := range append([]string{`pattern[0] "bad"`}, c.want...) {
			if !strings.Contains(message, want) {
				t.Errorf("%s: error %q does not mention %q", name, message, want)
			}
		}
	}
}
