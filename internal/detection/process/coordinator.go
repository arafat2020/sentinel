package process

import (
	"sync"

	"github.com/arafat2020/sentinel/internal/core"
	"github.com/arafat2020/sentinel/internal/finding"
)

// Coordinator runs the process rules when a process starts.
//
// It works in one of two ways, depending on how processes are collected.
// A polling collector hands it each snapshot (UpdateSnapshot) and the rules
// are evaluated over the latest one. An event-driven collector produces no
// snapshots; the coordinator is told what was running at the start (Track)
// and follows the events from there.
type Coordinator struct {
	engine *Engine
	sink   finding.Sink

	mu       sync.Mutex
	snapshot *core.ProcessSnapshot
	// live is the set of running processes by PID, kept up to date from
	// events. It is nil unless Track has been called.
	live map[int32]core.Process
}

func (c *Coordinator) UpdateSnapshot(
	snapshot *core.ProcessSnapshot,
) {
	c.mu.Lock()
	c.snapshot = snapshot
	c.mu.Unlock()
}

func NewCoordinator(
	engine *Engine,
	sink finding.Sink,
) *Coordinator {
	return &Coordinator{
		engine: engine,
		sink:   sink,
	}
}

// Track makes the coordinator follow process events instead of waiting to be
// handed snapshots. processes is what was running when collection started.
//
// The rules are then evaluated for each process as it starts or changes
// image, and for the children of a process that changes image, rather than
// for every process in a snapshot each time anything starts. Each
// parent-and-child pair is therefore reported once, when it comes about.
func (c *Coordinator) Track(processes []core.Process) {
	live := make(map[int32]core.Process, len(processes))
	for _, process := range processes {
		live[process.PID] = process
	}

	c.mu.Lock()
	c.live = live
	c.mu.Unlock()
}

// maxLive bounds the processes followed after Track. An event-driven
// collector reports every exit, so it is reached only if exits are lost;
// processes beyond it are not judged.
const maxLive = 1 << 17

func (c *Coordinator) Handle(
	event core.Event,
) []*core.Finding {
	// With no rule registered there is nothing to evaluate, and no reason
	// to keep track of processes for it.
	if !c.engine.HasRules() {
		return nil
	}

	c.mu.Lock()

	var findings []*core.Finding
	if c.live != nil {
		findings = c.follow(event)
	} else if event.Type == core.EventProcessStart && c.snapshot != nil {
		findings = c.engine.Evaluate(NewProcessTree(c.snapshot))
	}

	c.mu.Unlock()

	for _, finding := range findings {
		c.sink.Handle(finding)
	}

	return findings
}

// follow applies a process event to the live set and evaluates the rules for
// the processes whose results it can have changed.
func (c *Coordinator) follow(event core.Event) []*core.Finding {
	if event.Process == nil {
		return nil
	}
	process := *event.Process

	switch event.Type {
	case core.EventProcessExit:
		if known, ok := c.live[process.PID]; ok && known.Identity() == process.Identity() {
			delete(c.live, process.PID)
		}
		return nil

	case core.EventProcessStart, core.EventProcessExec:
		if _, known := c.live[process.PID]; !known && len(c.live) >= maxLive {
			return nil
		}
		c.live[process.PID] = process

	default:
		return nil
	}

	// The rules look at a process and its parent, so a small tree of the
	// process, its parent and (after an exec, which changes what it is as
	// a parent) its children holds everything they need.
	relevant := []core.Process{process}
	judged := []core.ProcessIdentity{process.Identity()}

	if parent, ok := c.live[process.PPID]; ok && parent.PID != process.PID {
		relevant = append(relevant, parent)
	}
	if event.Type == core.EventProcessExec {
		for _, other := range c.live {
			if other.PPID == process.PID && other.PID != process.PID {
				relevant = append(relevant, other)
				judged = append(judged, other.Identity())
			}
		}
	}

	tree := NewProcessTree(&core.ProcessSnapshot{Processes: relevant})
	return c.engine.EvaluateProcesses(tree, judged)
}
