package config

import (
	"os"
	"strings"
	"testing"
)

// yamlBlocks returns the fenced yaml code blocks of a Markdown file.
func yamlBlocks(t *testing.T, path string) []string {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	var blocks []string
	parts := strings.Split(string(data), "```")
	for i := 1; i < len(parts); i += 2 {
		if body, isYAML := strings.CutPrefix(parts[i], "yaml\n"); isYAML {
			blocks = append(blocks, body)
		}
	}
	return blocks
}

func indent(text, prefix string) string {
	lines := strings.Split(strings.TrimRight(text, "\n"), "\n")
	for i, line := range lines {
		if line != "" {
			lines[i] = prefix + line
		}
	}
	return strings.Join(lines, "\n") + "\n"
}

// Every complete pattern, patterns file and exclusions list shown in the
// guide must load without error: an example that does not work is worse than
// none.
func TestDocumentedExamplesLoad(t *testing.T) {
	const guide = "../../docs/behavioral-patterns.md"

	patterns, files, exclusions := 0, 0, 0

	for _, block := range yamlBlocks(t, guide) {
		var content string

		switch {
		case strings.HasPrefix(block, "patterns:"):
			content = block
			files++
		case strings.HasPrefix(block, "- name:"):
			content = "patterns:\n" + indent(block, "  ")
			patterns++
		case strings.HasPrefix(block, "exclusions:"):
			content = "patterns: []\n" + block
			exclusions++
		default:
			continue // a fragment illustrating one key
		}

		set, err := LoadPatterns(writeFile(t, content))
		if err != nil {
			t.Errorf("example does not parse: %v\n%s", err, block)
			continue
		}
		for _, problem := range set.Errors {
			t.Errorf("example is rejected: %v\n%s", problem, block)
		}
		if len(set.Patterns)+len(set.Exclusions) == 0 {
			t.Errorf("example loaded nothing:\n%s", block)
		}
	}

	// The guide promises a full file, three worked examples and exclusions.
	if files < 1 || patterns < 3 || exclusions < 2 {
		t.Fatalf("found %d file example(s), %d pattern example(s), %d exclusions example(s); the extraction is missing some",
			files, patterns, exclusions)
	}
}
