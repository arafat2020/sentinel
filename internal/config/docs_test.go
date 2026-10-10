package config

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/arafat2020/sentinel/internal/core"
	"github.com/arafat2020/sentinel/internal/detection/correlation"
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
	if files < 1 || patterns < 7 || exclusions < 2 {
		t.Fatalf("found %d file example(s), %d pattern example(s), %d exclusions example(s); the extraction is missing some",
			files, patterns, exclusions)
	}
}

// guideExamples loads every complete pattern shown in the guide, by name.
func guideExamples(t *testing.T) map[string]correlation.BehaviorPattern {
	t.Helper()

	examples := make(map[string]correlation.BehaviorPattern)
	for _, block := range yamlBlocks(t, "../../docs/behavioral-patterns.md") {
		if !strings.HasPrefix(block, "- name:") {
			continue
		}

		set, err := LoadPatterns(writeFile(t, "patterns:\n"+indent(block, "  ")))
		if err != nil || len(set.Errors) != 0 {
			t.Fatalf("example does not load: %v %v", err, set.Errors)
		}
		for _, pattern := range set.Patterns {
			examples[pattern.Name] = pattern
		}
	}

	return examples
}

// scenario plays events into an engine loaded with one documented example.
type scenario struct {
	t      *testing.T
	engine *correlation.Engine
	now    time.Time
	start  time.Time
}

func newScenario(t *testing.T, pattern correlation.BehaviorPattern) *scenario {
	t.Helper()

	s := &scenario{t: t, start: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
	s.now = s.start
	s.engine = correlation.NewEngine(correlation.DefaultWindow, correlation.WithClock(func() time.Time { return s.now }))
	s.engine.SetPatterns([]correlation.BehaviorPattern{pattern})

	return s
}

// at sends an event that happened, and was observed, offset after the start.
func (s *scenario) at(offset time.Duration, event core.Event, process core.Process) {
	s.now = s.start.Add(offset)
	event.Timestamp = s.now
	event.Process = &process
	s.engine.Process(event)
}

func (s *scenario) started(offset time.Duration, process core.Process) {
	s.at(offset, core.Event{Type: core.EventProcessStart}, process)
}

func (s *scenario) connected(offset time.Duration, process core.Process, addr string, port uint32) {
	s.at(offset, core.Event{
		Type:    core.EventNetworkConnect,
		Network: &core.NetworkConnection{RemoteAddress: addr, RemotePort: port, Protocol: "tcp"},
	}, process)
}

func (s *scenario) created(offset time.Duration, process core.Process, path string) {
	s.at(offset, core.Event{Type: core.EventFileCreate, File: &core.FileEvent{Path: path}}, process)
}

func (s *scenario) queried(offset time.Duration, process core.Process, domain string) {
	s.at(offset, core.Event{Type: core.EventDNSQuery, DNS: &core.DNSQuery{Domain: domain, Type: "A"}}, process)
}

// findings evaluates the pattern offset after the start.
func (s *scenario) findings(offset time.Duration) []core.Finding {
	s.now = s.start.Add(offset)
	return s.engine.DetectBehaviors()
}

func process(pid, ppid int32, name, exe string) core.Process {
	return core.Process{
		PID: pid, PPID: ppid, Name: name, Executable: exe, User: "www-data",
		StartTime: time.Date(2026, 1, 1, 11, 0, 0, 0, time.UTC).Add(time.Duration(pid) * time.Second),
	}
}

// Every worked example in the guide is run against activity it should catch
// and activity it should not.
func TestDocumentedExamplesBehaveAsDescribed(t *testing.T) {
	examples := guideExamples(t)

	type run func(s *scenario)

	cases := []struct {
		example  string
		scenario string
		want     int
		play     run
	}{
		// 1. webshell-outbound
		{"webshell-outbound", "nginx spawns sh, which connects to a public address on port 4444", 1, func(s *scenario) {
			web, shell := process(10, 1, "nginx", "/usr/sbin/nginx"), process(20, 10, "sh", "/bin/sh")
			s.started(0, web)
			s.started(time.Second, shell)
			s.connected(2*time.Second, shell, "203.0.113.9", 4444)
		}},
		{"webshell-outbound", "the shell only talks HTTPS", 0, func(s *scenario) {
			web, shell := process(10, 1, "nginx", "/usr/sbin/nginx"), process(20, 10, "sh", "/bin/sh")
			s.started(0, web)
			s.started(time.Second, shell)
			s.connected(2*time.Second, shell, "203.0.113.9", 443)
		}},

		// 2. tmp-exec-network
		{"tmp-exec-network", "a program in /tmp connects out", 1, func(s *scenario) {
			p := process(30, 1, "x", "/tmp/.cache/x")
			s.started(0, p)
			s.connected(time.Second, p, "198.51.100.7", 8443)
		}},
		{"tmp-exec-network", "a program in /usr/bin connects out", 0, func(s *scenario) {
			p := process(30, 1, "curl", "/usr/bin/curl")
			s.started(0, p)
			s.connected(time.Second, p, "198.51.100.7", 8443)
		}},

		// 3. interpreter-suspicious-tld
		{"interpreter-suspicious-tld", "python resolves a .top domain", 1, func(s *scenario) {
			p := process(40, 1, "python3.12", "/usr/bin/python3.12")
			s.started(0, p)
			s.queried(time.Second, p, "updates.badsite.top")
		}},
		{"interpreter-suspicious-tld", "python resolves an ordinary domain", 0, func(s *scenario) {
			p := process(40, 1, "python3.12", "/usr/bin/python3.12")
			s.started(0, p)
			s.queried(time.Second, p, "pypi.org")
			s.queried(2*time.Second, p, "top.example.com")
		}},

		// 4. download-and-execute
		{"download-and-execute", "sh runs curl, which connects and creates /tmp/payload; sh then runs /tmp/payload", 1, func(s *scenario) {
			shell, curl, payload := process(50, 1, "sh", "/bin/sh"), process(55, 50, "curl", "/usr/bin/curl"), process(60, 50, "payload", "/tmp/payload")
			s.started(0, shell)
			s.started(500*time.Millisecond, curl)
			s.connected(time.Second, curl, "203.0.113.9", 443)
			s.created(2*time.Second, curl, "/tmp/payload")
			s.started(3*time.Second, payload)
		}},
		{"download-and-execute", "the shell then runs something other than the file created", 0, func(s *scenario) {
			shell, curl, other := process(50, 1, "sh", "/bin/sh"), process(55, 50, "curl", "/usr/bin/curl"), process(60, 50, "id", "/usr/bin/id")
			s.started(0, shell)
			s.started(500*time.Millisecond, curl)
			s.connected(time.Second, curl, "203.0.113.9", 443)
			s.created(2*time.Second, curl, "/tmp/payload")
			s.started(3*time.Second, other)
		}},
		{"download-and-execute", "the file is created long before the connection", 0, func(s *scenario) {
			shell, curl, payload := process(50, 1, "sh", "/bin/sh"), process(55, 50, "curl", "/usr/bin/curl"), process(60, 50, "payload", "/tmp/payload")
			s.started(0, shell)
			s.started(500*time.Millisecond, curl)
			s.created(time.Second, curl, "/tmp/payload")
			s.connected(20*time.Second, curl, "203.0.113.9", 443)
			s.started(21*time.Second, payload)
		}},
		{"download-and-execute", "the file is run by an unrelated process, not the one that started the download", 0, func(s *scenario) {
			shell, curl, payload := process(50, 1, "sh", "/bin/sh"), process(55, 50, "curl", "/usr/bin/curl"), process(60, 1, "payload", "/tmp/payload")
			s.started(0, shell)
			s.started(500*time.Millisecond, curl)
			s.connected(time.Second, curl, "203.0.113.9", 443)
			s.created(2*time.Second, curl, "/tmp/payload")
			s.started(3*time.Second, payload)
		}},

		// 5. webshell-outbound-any-depth
		{"webshell-outbound-any-depth", "nginx → php-fpm → sh, and sh connects to port 4444", 1, func(s *scenario) {
			web, fpm, shell := process(10, 1, "nginx", ""), process(11, 10, "php-fpm", ""), process(12, 11, "sh", "")
			s.started(0, web)
			s.started(time.Second, fpm)
			s.started(2*time.Second, shell)
			s.connected(3*time.Second, shell, "203.0.113.9", 4444)
		}},
		{"webshell-outbound-any-depth", "the shell is five generations down", 0, func(s *scenario) {
			previous := process(10, 1, "nginx", "")
			s.started(0, previous)
			for i := int32(1); i <= 4; i++ {
				next := process(10+i, previous.PID, "worker", "")
				s.started(time.Duration(i)*time.Second, next)
				previous = next
			}
			shell := process(20, previous.PID, "sh", "")
			s.started(6*time.Second, shell)
			s.connected(7*time.Second, shell, "203.0.113.9", 4444)
		}},
		{"webshell-outbound-any-depth", "the shell descends from sshd, not a web server", 0, func(s *scenario) {
			sshd, shell := process(10, 1, "sshd", ""), process(12, 10, "sh", "")
			s.started(0, sshd)
			s.started(time.Second, shell)
			s.connected(2*time.Second, shell, "203.0.113.9", 4444)
		}},

		// 6. dns-tunnelling
		{"dns-tunnelling", "100 distinct names under the domain in 50 seconds", 1, func(s *scenario) {
			p := process(70, 1, "iodine", "")
			s.started(0, p)
			for i := 0; i < 100; i++ {
				s.queried(time.Second+time.Duration(i)*500*time.Millisecond, p, fmt.Sprintf("chunk%03d.tunnel.example", i))
			}
		}},
		{"dns-tunnelling", "99 distinct names, however often repeated", 0, func(s *scenario) {
			p := process(70, 1, "iodine", "")
			s.started(0, p)
			for i := 0; i < 400; i++ {
				s.queried(time.Second+time.Duration(i)*100*time.Millisecond, p, fmt.Sprintf("chunk%03d.tunnel.example", i%99))
			}
		}},
		{"dns-tunnelling", "100 distinct names spread over four minutes", 0, func(s *scenario) {
			p := process(70, 1, "resolver", "")
			s.started(0, p)
			for i := 0; i < 100; i++ {
				s.queried(time.Second+time.Duration(i)*2400*time.Millisecond, p, fmt.Sprintf("chunk%03d.tunnel.example", i))
			}
		}},
		{"dns-tunnelling", "100 distinct names under other domains", 0, func(s *scenario) {
			p := process(70, 1, "browser", "")
			s.started(0, p)
			for i := 0; i < 100; i++ {
				s.queried(time.Second+time.Duration(i)*100*time.Millisecond, p, fmt.Sprintf("site%03d.example.org", i))
			}
		}},

		// 7. interpreter-persistence-after-connect
		{"interpreter-persistence-after-connect", "python connects out, then writes a cron file 10s later", 1, func(s *scenario) {
			p := process(80, 1, "python3", "/usr/bin/python3")
			s.started(0, p)
			s.connected(time.Second, p, "203.0.113.9", 443)
			s.created(11*time.Second, p, "/etc/cron.d/updater")
		}},
		{"interpreter-persistence-after-connect", "the write comes 45s after the connection", 0, func(s *scenario) {
			p := process(80, 1, "python3", "/usr/bin/python3")
			s.started(0, p)
			s.connected(time.Second, p, "203.0.113.9", 443)
			s.created(46*time.Second, p, "/etc/cron.d/updater")
		}},
		{"interpreter-persistence-after-connect", "python writes somewhere harmless", 0, func(s *scenario) {
			p := process(80, 1, "python3", "/usr/bin/python3")
			s.started(0, p)
			s.connected(time.Second, p, "203.0.113.9", 443)
			s.created(5*time.Second, p, "/tmp/output.json")
		}},
		{"interpreter-persistence-after-connect", "a shell does the same thing", 0, func(s *scenario) {
			p := process(80, 1, "bash", "/bin/bash")
			s.started(0, p)
			s.connected(time.Second, p, "203.0.113.9", 443)
			s.created(5*time.Second, p, "/etc/cron.d/updater")
		}},
	}

	covered := map[string][2]bool{} // example → saw a positive, saw a negative

	for _, c := range cases {
		pattern, ok := examples[c.example]
		if !ok {
			t.Errorf("the guide has no example named %q", c.example)
			continue
		}

		s := newScenario(t, pattern)
		c.play(s)

		got := s.findings(4*time.Minute + 30*time.Second)
		if len(got) != c.want {
			t.Errorf("%s — %s: findings = %d, want %d", c.example, c.scenario, len(got), c.want)
		}
		for _, f := range got {
			if f.Rule != c.example || len(f.Evidence.Roles) != len(pattern.Processes) {
				t.Errorf("%s: finding %q with roles %v", c.example, f.Rule, f.Evidence.Roles)
			}
		}

		seen := covered[c.example]
		seen[0] = seen[0] || c.want > 0
		seen[1] = seen[1] || c.want == 0
		covered[c.example] = seen
	}

	// Every example in the guide must be exercised both ways.
	for name := range examples {
		if seen := covered[name]; !seen[0] || !seen[1] {
			t.Errorf("example %q lacks a positive or a negative scenario (positive=%v negative=%v)", name, seen[0], seen[1])
		}
	}
}
