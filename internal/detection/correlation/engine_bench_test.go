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

// benchWorld builds a process tree of 1,000 processes (100 parents with nine
// children each) and a stream of 50,000 events spread across them at 100
// events per second.
func benchWorld(start time.Time) ([]core.Process, []core.Event) {
	names := []string{"node", "python", "bash", "nginx", "postgres", "sshd", "cron", "java", "go", "curl"}

	processes := make([]core.Process, 0, benchProcesses)
	for parent := 0; parent < benchProcesses/10; parent++ {
		parentPID := int32(1000 + parent*10)
		processes = append(processes, core.Process{
			PID: parentPID, PPID: 1, Name: names[parent%len(names)], StartTime: start.Add(-time.Hour),
		})
		for child := 1; child < 10; child++ {
			processes = append(processes, core.Process{
				PID: parentPID + int32(child), PPID: parentPID,
				Name: names[(parent+child)%len(names)], StartTime: start.Add(-time.Minute),
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
		events[i] = core.Event{
			Type:      eventTypes[(i*31)%len(eventTypes)],
			Timestamp: start.Add(time.Duration(i) * 10 * time.Millisecond),
			Process:   process,
		}
	}

	return processes, events
}

// BenchmarkEngineProcess measures the per-event cost of the path the event
// bus drives: Process followed by DetectBehaviors, with 1,000 known
// processes, ten patterns and a five-minute window.
func BenchmarkEngineProcess(b *testing.B) {
	start := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	processes, events := benchWorld(start)

	now := start
	engine := NewEngine(5*time.Minute, WithClock(func() time.Time { return now }))
	engine.SetPatterns(benchPatternSet())
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
