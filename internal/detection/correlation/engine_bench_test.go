package correlation

import (
	"fmt"
	"testing"
	"time"

	"github.com/arafat2020/sentinel/internal/core"
)

const (
	benchProcesses = 1000
	benchEvents    = 50000
	benchPatterns  = 10
)

// benchPatternSet is the default pattern plus variations that look for other
// interpreters and event types, so most evaluations find nothing, as in
// normal operation.
func benchPatternSet() []BehaviorPattern {
	children := []string{"python", "bash", "sh", "perl", "ruby", "node", "php", "curl", "nc"}
	eventTypes := []core.EventType{core.EventNetworkConnect, core.EventDNSQuery, core.EventFileCreate}

	patterns := DefaultPatterns()
	for i := 0; len(patterns) < benchPatterns; i++ {
		eventType := eventTypes[i%len(eventTypes)]
		patterns = append(patterns, BehaviorPattern{
			Name:     fmt.Sprintf("bench-%d", i),
			Severity: core.SeverityLow,
			Processes: []ProcessPattern{
				{ID: "parent", Events: []EventPattern{{Type: core.EventNetworkConnect}}},
				{
					ID:         "child",
					Conditions: []Condition{{Type: ConditionProcessName, Value: children[i%len(children)]}},
					Events:     []EventPattern{{Type: eventType}},
				},
			},
			Relationships: []RelationshipPattern{
				{Type: RelationshipSpawned, Parent: "parent", Child: "child"},
			},
		})
	}

	return patterns
}

// benchPredicatePatternSet is ten patterns built from the predicate schema:
// regex, glob, prefix and nocase process matches, any_of, event filters with
// numeric and CIDR operators, and a per-pattern exclusion.
func benchPredicatePatternSet() []BehaviorPattern {
	interpreters := []string{`^python[0-9.]*$`, `^(ba|z|da)?sh$`, `^perl[0-9.]*$`, `^ruby[0-9.]*$`, `^node(js)?$`}
	privateNetworks := []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "::1/128", "fc00::/7"}

	var patterns []BehaviorPattern
	for i := 0; len(patterns) < benchPatterns; i++ {
		pattern := BehaviorPattern{
			Name:     fmt.Sprintf("bench-predicates-%d", i),
			Severity: core.SeverityLow,
			Processes: []ProcessPattern{
				{
					ID: "parent",
					Match: &MatchBlock{Fields: []FieldPredicate{
						{Field: "user", Predicate: Predicate{Not: &Predicate{Eq: stringPtr("root")}}},
					}},
					Events: []EventPattern{{Type: core.EventNetworkConnect}},
				},
				{
					ID: "child",
					Match: &MatchBlock{
						Fields: []FieldPredicate{
							{Field: "name", Predicate: Predicate{Regex: stringPtr(interpreters[i%len(interpreters)])}},
						},
						AnyOf: []MatchBlock{
							{Fields: []FieldPredicate{{Field: "exe", Predicate: Predicate{Glob: stringPtr("/tmp/**")}}}},
							{Fields: []FieldPredicate{{Field: "exe", Predicate: Predicate{Prefix: stringPtr("/USR/"), NoCase: true}}}},
						},
					},
					Events: []EventPattern{
						{
							Type: core.EventNetworkConnect,
							Where: &MatchBlock{Fields: []FieldPredicate{
								{Field: "remote_port", Predicate: Predicate{Not: &Predicate{In: []string{"80", "443", "53"}}}},
								{Field: "remote_addr", Predicate: Predicate{Not: &Predicate{CIDR: privateNetworks}}},
							}},
						},
						{
							Type: core.EventDNSQuery,
							Where: &MatchBlock{Fields: []FieldPredicate{
								{Field: "domain", Predicate: Predicate{Regex: stringPtr(`\.(ru|top|xyz|click)$`)}},
							}},
						},
					},
				},
			},
			Relationships: []RelationshipPattern{
				{Type: RelationshipSpawned, Parent: "parent", Child: "child"},
			},
			Exclude: []RoleExclusion{{Role: "parent", Match: &MatchBlock{Fields: []FieldPredicate{
				{Field: "name", Predicate: Predicate{In: []string{"sshd", "cron"}}},
			}}}},
		}
		patterns = append(patterns, pattern)
	}

	return patterns
}

// benchWorld builds a process tree of 1,000 processes (100 parents with nine
// children each) and a stream of 50,000 events spread across them at 100
// events per second.
//
// With mixed false each process only ever produces one type of event, which
// is the stream Phase 1 was measured on. With mixed true the event types
// rotate, so a process accumulates several types and patterns that require
// more than one can match.
func benchWorld(start time.Time, mixed bool) ([]core.Process, []core.Event) {
	names := []string{"node", "python", "bash", "nginx", "postgres", "sshd", "cron", "java", "go", "curl"}
	users := []string{"root", "www-data", "app", "deploy"}
	directories := []string{"/usr/bin/", "/tmp/", "/opt/app/bin/"}
	addresses := []string{"10.0.0.5", "93.184.216.34", "192.168.1.20", "2001:db8::10", "::1", "203.0.113.77"}
	ports := []uint32{443, 80, 53, 4444, 8080, 22}
	domains := []string{"example.com", "api.github.com", "c2.evil.top", "cdn.vendor.io", "tracker.bad.ru"}

	processes := make([]core.Process, 0, benchProcesses)
	for parent := 0; parent < benchProcesses/10; parent++ {
		parentPID := int32(1000 + parent*10)
		processes = append(processes, core.Process{
			PID: parentPID, PPID: 1, Name: names[parent%len(names)], StartTime: start.Add(-time.Hour),
			User: users[parent%len(users)], Executable: "/usr/bin/" + names[parent%len(names)],
		})
		for child := 1; child < 10; child++ {
			name := names[(parent+child)%len(names)]
			processes = append(processes, core.Process{
				PID: parentPID + int32(child), PPID: parentPID,
				Name: name, StartTime: start.Add(-time.Minute),
				User: users[(parent+child)%len(users)], Executable: directories[child%len(directories)] + name,
				CommandLine: name + " -c run",
			})
		}
	}

	eventTypes := []core.EventType{
		core.EventNetworkConnect, core.EventNetworkClose, core.EventDNSQuery,
		core.EventFileCreate, core.EventFileModify,
	}

	events := make([]core.Event, benchEvents)
	for i := range events {
		// A fixed stride visits every process without clustering.
		process := &processes[(i*7919)%len(processes)]
		kind := i * 31
		if mixed {
			kind += i / len(processes)
		}

		events[i] = core.Event{
			Type:      eventTypes[kind%len(eventTypes)],
			Timestamp: start.Add(time.Duration(i) * 10 * time.Millisecond),
			Process:   process,
		}

		// Events carry the details that filters read, as real ones do.
		switch events[i].Type {
		case core.EventNetworkConnect, core.EventNetworkClose:
			events[i].Network = &core.NetworkConnection{
				RemoteAddress: addresses[(i*13)%len(addresses)],
				RemotePort:    ports[(i*17)%len(ports)],
				Protocol:      "tcp",
			}
		case core.EventDNSQuery:
			events[i].DNS = &core.DNSQuery{Domain: domains[(i*19)%len(domains)], Type: "A"}
		case core.EventFileCreate, core.EventFileModify:
			events[i].File = &core.FileEvent{Path: "/var/log/app.log"}
		}
	}

	return processes, events
}

// BenchmarkEngineProcess measures the per-event cost of the path the event
// bus drives: Process followed by DetectBehaviors, with 1,000 known
// processes, ten patterns and a five-minute window. Nine of the patterns are
// in the original form: an exact name condition and bare event types.
func BenchmarkEngineProcess(b *testing.B) {
	benchmarkEngine(b, benchPatternSet(), nil, false)
}

// BenchmarkEngineProcessPredicates is the same number of processes, events
// and patterns, with every pattern using regex, glob, CIDR and numeric
// predicates, event filters, any_of and exclusions.
func BenchmarkEngineProcessPredicates(b *testing.B) {
	patterns := benchPredicatePatternSet()
	for _, pattern := range patterns {
		if err := pattern.Validate(); err != nil {
			b.Fatalf("pattern %q: %v", pattern.Name, err)
		}
	}

	exclusions := []Exclusion{
		{Rules: []string{"*"}, Match: &MatchBlock{Fields: []FieldPredicate{
			{Field: "exe", Predicate: Predicate{Prefix: stringPtr("/opt/app/")}},
		}}},
	}

	benchmarkEngine(b, patterns, exclusions, true)
}

func benchmarkEngine(b *testing.B, patterns []BehaviorPattern, exclusions []Exclusion, mixed bool) {
	start := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	processes, events := benchWorld(start, mixed)

	now := start
	engine := NewEngine(5*time.Minute, WithClock(func() time.Time { return now }))
	engine.SetPatterns(patterns)
	if err := engine.SetExclusions(exclusions); err != nil {
		b.Fatal(err)
	}
	engine.Seed(processes)

	findings := 0

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		event := events[i%len(events)]
		// Keep time moving forward when the stream wraps around.
		now = event.Timestamp.Add(time.Duration(i/len(events)) * benchEvents * 10 * time.Millisecond)
		event.Timestamp = now

		engine.Process(event)
		findings += len(engine.DetectBehaviors())
	}

	b.StopTimer()
	b.ReportMetric(float64(findings)/float64(b.N), "findings/op")
}
