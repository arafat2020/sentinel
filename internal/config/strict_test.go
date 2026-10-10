package config

import (
	"strings"
	"testing"
)

// An unknown key anywhere inside a pattern or exclusion is an error naming
// the pattern and the path to the key. Before, it was dropped in silence and
// the pattern loaded meaning something other than what was written.
func TestUnknownKeysAreRejectedWithTheirPath(t *testing.T) {
	const prefix = "patterns:\n    - name: bad\n"

	cases := map[string]struct {
		body string
		path string
	}{
		"pattern level": {
			"      severty: HIGH\n      processes:\n        - id: a\n",
			"severty",
		},
		"role level": {
			"      processes:\n        - id: a\n        - id: b\n          mach:\n            name: x\n      relationships:\n        - {type: SPAWNED, parent: a, child: b}\n",
			"processes[1].mach",
		},
		"condition level": {
			"      processes:\n        - id: a\n          conditions:\n            - {type: PROCESS_NAME, value: x, nocase: true}\n",
			"processes[0].conditions[0].nocase",
		},
		"event level": {
			"      processes:\n        - id: a\n          events:\n            - type: DNS_QUERY\n            - type: NETWORK_CONNECT\n              were:\n                remote_port: 22\n",
			"processes[0].events[1].were",
		},
		"relationship level": {
			"      processes:\n        - id: a\n        - id: b\n      relationships:\n        - {type: DESCENDANT, parent: a, child: b, maxdepth: 3}\n",
			"relationships[0].maxdepth",
		},
		"exclude level": {
			"      processes:\n        - id: a\n      exclude:\n        - role: a\n          match:\n            name: x\n          reason: noisy\n",
			"exclude[0].reason",
		},
		"sequence level": {
			"      processes:\n        - id: a\n      sequence:\n        withn: 10s\n        steps:\n          - {role: a, type: DNS_QUERY}\n",
			"sequence.withn",
		},
		"sequence step level": {
			"      processes:\n        - id: a\n      sequence:\n        steps:\n          - {role: a, type: DNS_QUERY}\n          - {role: a, type: NETWORK_CONNECT, captur: c}\n",
			"sequence.steps[1].captur",
		},
	}

	for name, c := range cases {
		set, err := LoadPatterns(writeFile(t, prefix+c.body))
		if err != nil {
			t.Errorf("%s: the whole file was rejected: %v", name, err)
			continue
		}
		if len(set.Patterns) != 0 || len(set.Errors) != 1 {
			t.Errorf("%s: loaded %d patterns with %d errors, want 0 and 1: %v", name, len(set.Patterns), len(set.Errors), set.Errors)
			continue
		}

		message := set.Errors[0].Error()
		for _, want := range []string{`pattern[0] "bad"`, c.path + ": unknown key"} {
			if !strings.Contains(message, want) {
				t.Errorf("%s: error %q does not mention %q", name, message, want)
			}
		}
		if len(set.Warnings) != 0 {
			t.Errorf("%s: unexpected warnings %q", name, set.Warnings)
		}
	}
}

func TestUnknownKeyErrorListsTheValidOnes(t *testing.T) {
	set, _ := LoadPatterns(writeFile(t, "patterns:\n    - name: bad\n      processes:\n        - id: a\n          evnts: []\n"))
	if len(set.Errors) != 1 {
		t.Fatalf("errors = %v", set.Errors)
	}
	if got := set.Errors[0].Error(); !strings.Contains(got, "valid keys here: conditions, events, id, match") {
		t.Errorf("error %q does not list the valid keys", got)
	}
}

func TestUnknownKeyInExclusionIsRejected(t *testing.T) {
	set, err := LoadPatterns(writeFile(t, `patterns: []
exclusions:
    - rules: ["*"]
      match:
        name: python
    - rules: ["*"]
      match:
        name: bash
      desciption: typo
`))
	if err != nil {
		t.Fatal(err)
	}
	if len(set.Exclusions) != 1 || len(set.Errors) != 1 {
		t.Fatalf("loaded %d exclusions with %d errors, want 1 and 1", len(set.Exclusions), len(set.Errors))
	}
	if got := set.Errors[0].Error(); !strings.Contains(got, "exclusions[1]: desciption: unknown key") {
		t.Errorf("error = %q", got)
	}
}

// One bad key costs one pattern, not the file.
func TestUnknownKeyKeepsPartialLoading(t *testing.T) {
	set, err := LoadPatterns(writeFile(t, `patterns:
    - name: good-one
      processes:
        - id: a
    - name: typo
      processes:
        - id: a
          match:
            name: x
          evnts: []
    - name: good-two
      processes:
        - id: a
`))
	if err != nil {
		t.Fatal(err)
	}
	if len(set.Patterns) != 2 || len(set.Errors) != 1 || set.Errors[0].Name != "typo" || set.Errors[0].Index != 1 {
		t.Fatalf("patterns=%d errors=%v", len(set.Patterns), set.Errors)
	}
}

// Field names inside match and where blocks are not keys of the schema; they
// are checked against the thing being matched, with their own message.
func TestFieldNamesAreNotTreatedAsUnknownKeys(t *testing.T) {
	set, _ := LoadPatterns(writeFile(t, "patterns:\n    - name: bad\n      processes:\n        - id: a\n          match:\n            colour: red\n"))
	if len(set.Errors) != 1 {
		t.Fatalf("errors = %v", set.Errors)
	}
	got := set.Errors[0].Error()
	if !strings.Contains(got, "match.colour: unknown field") || strings.Contains(got, "unknown key") {
		t.Errorf("error = %q, want the unknown-field message", got)
	}
}

func TestUnknownTopLevelKeyIsAWarning(t *testing.T) {
	set, err := LoadPatterns(writeFile(t, `version: 2
patterns:
    - name: fine
      processes:
        - id: a
settings:
    window: 5m
exclusions: []
`))
	if err != nil {
		t.Fatalf("an unknown top-level key rejected the file: %v", err)
	}
	if len(set.Patterns) != 1 || len(set.Errors) != 0 {
		t.Fatalf("patterns=%d errors=%v, want the pattern loaded and no errors", len(set.Patterns), set.Errors)
	}
	if len(set.Warnings) != 2 {
		t.Fatalf("warnings = %q, want one per unknown key", set.Warnings)
	}
	for i, key := range []string{"version", "settings"} {
		if !strings.Contains(set.Warnings[i], `unknown top-level key "`+key+`"`) {
			t.Errorf("warning %d = %q, want it to name %q", i, set.Warnings[i], key)
		}
	}

	// The shipped file and the fixtures have nothing to warn about.
	for _, path := range []string{shippedPatterns, v1Patterns, v2Patterns} {
		if clean := mustLoad(t, path); len(clean.Warnings) != 0 {
			t.Errorf("%s: unexpected warnings %q", path, clean.Warnings)
		}
	}
}
