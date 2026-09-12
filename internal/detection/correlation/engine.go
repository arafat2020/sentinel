package correlation

import (
	"time"

	"github.com/arafat2020/sentinel/internal/core"
)

type Engine struct {
	state         *State
	chains        map[core.ProcessIdentity][]*Chain
	relationships map[core.ProcessIdentity][]ProcessRelationship
	processes     map[int32]core.Process
	window        time.Duration
	patterns      []BehaviorPattern
	matcher       *Matcher
	emitted       map[string]time.Time // rule name → last emitted time
}

func NewEngine(window time.Duration) *Engine {
	return &Engine{
		state:         NewStateWithWindow(window),
		chains:        make(map[core.ProcessIdentity][]*Chain),
		relationships: make(map[core.ProcessIdentity][]ProcessRelationship),
		processes:     make(map[int32]core.Process),
		window:        window,
		patterns:      DefaultPatterns(),
		matcher:       NewMatcher(),
		emitted:       make(map[string]time.Time),
	}
}

func (e *Engine) Process(event core.Event) {
	if event.Process == nil {
		return
	}

	process := *event.Process
	identity := process.Identity()

	// Discover parent → child relationship only when a process starts.
	if event.Type == core.EventProcessStart {
		if parent, ok := e.processes[process.PPID]; ok {
			relationship := NewProcessRelationship(
				parent,
				process,
			)

			e.relationships[identity] = append(
				e.relationships[identity],
				relationship,
			)
		}

		// Remember this process for future children.
		e.processes[process.PID] = process
	}

	// Every event belongs to the process's correlation state.
	e.state.Add(event)

	chains := e.chains[identity]

	if len(chains) == 0 {
		e.chains[identity] = []*Chain{
			NewChain(event),
		}
		return
	}

	// For now, append to the latest chain.
	latest := chains[len(chains)-1]

	if latest.Add(event) {
		return
	}

	// The event could not belong to the latest chain.
	e.chains[identity] = append(
		chains,
		NewChain(event),
	)
}
func (e *Engine) ChainsForProcess(
	identity core.ProcessIdentity,
) []*Chain {
	return e.chains[identity]
}

func (e *Engine) RelationshipsForProcess(
	identity core.ProcessIdentity,
) []ProcessRelationship {
	return e.relationships[identity]
}

func hasNetworkActivity(chains []*Chain) bool {
	for _, chain := range chains {
		for _, event := range chain.Events() {
			if event.Type == core.EventNetworkConnect {
				return true
			}
		}
	}

	return false
}

// DetectBehaviors evaluates all registered patterns against the accumulated
// correlation state and returns any newly triggered findings. A finding for a
// given rule is suppressed until at least one window duration has elapsed since
// it was last emitted, preventing duplicate alerts for a sustained behaviour.
func (e *Engine) DetectBehaviors() []core.Finding {
	var findings []core.Finding

	now := time.Now()
	relationships := e.allRelationships()

	for _, pattern := range e.patterns {
		if !e.matcher.MatchPattern(pattern, relationships, e.chains) {
			continue
		}

		// Suppress if the same rule fired within the current window.
		if last, ok := e.emitted[pattern.Name]; ok && now.Sub(last) < e.window {
			continue
		}

		e.emitted[pattern.Name] = now

		findings = append(findings, core.Finding{
			Timestamp:   now,
			Rule:        pattern.Name,
			Severity:    pattern.Severity,
			Title:       pattern.Title,
			Description: pattern.Description,
		})
	}

	return findings
}
func (e *Engine) allRelationships() []ProcessRelationship {
	var relationships []ProcessRelationship

	for _, processRelationships := range e.relationships {
		relationships = append(
			relationships,
			processRelationships...,
		)
	}

	return relationships
}
