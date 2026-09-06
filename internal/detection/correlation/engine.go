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
}

func NewEngine(window time.Duration) *Engine {
	return &Engine{
		state:         NewStateWithWindow(window),
		chains:        make(map[core.ProcessIdentity][]*Chain),
		relationships: make(map[core.ProcessIdentity][]ProcessRelationship),
		processes:     make(map[int32]core.Process),
		window:        window,
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

func (e *Engine) DetectBehaviors() []core.Finding {
	var findings []core.Finding

	for childIdentity, relationships := range e.relationships {
		childChains := e.chains[childIdentity]

		for _, relationship := range relationships {
			if relationship.Child.Name != "python" {
				continue
			}

			parentChains := e.chains[relationship.Parent.Identity()]

			if !hasNetworkActivity(parentChains) {
				continue
			}

			if !hasNetworkActivity(childChains) {
				continue
			}

			findings = append(findings, core.Finding{
				ID:        "network-active-parent-spawns-python",
				Timestamp: time.Now(),
				Severity:  core.SeverityMedium,
				Rule:      "network-active-parent-spawns-python",
				Title:     "Network-active process spawned Python",
				Description: "A process with network activity spawned Python, " +
					"which subsequently established a network connection.",
				Evidence: core.Evidence{
					Processes: []core.Process{
						relationship.Parent,
						relationship.Child,
					},
				},
			})
		}
	}

	return findings
}
