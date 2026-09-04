package process

import "github.com/arafat2020/sentinel/internal/core"

type ProcessTree struct {
	processes map[core.ProcessIdentity]core.Process
	children  map[core.ProcessIdentity][]core.Process
	parents   map[core.ProcessIdentity]core.Process
}

func NewProcessTree(snapshot *core.ProcessSnapshot) *ProcessTree {
	tree := &ProcessTree{
		children:  make(map[core.ProcessIdentity][]core.Process),
		parents:   make(map[core.ProcessIdentity]core.Process),
		processes: make(map[core.ProcessIdentity]core.Process),
	}

	processesByPID := make(map[int32]core.Process)

	for _, process := range snapshot.Processes {
		processesByPID[process.PID] = process
		tree.processes[process.Identity()] = process
	}

	for _, process := range snapshot.Processes {
		parent, exists := processesByPID[process.PPID]
		if !exists {
			continue
		}

		parentIdentity := parent.Identity()
		childIdentity := process.Identity()

		tree.children[parentIdentity] = append(
			tree.children[parentIdentity],
			process,
		)
		tree.parents[childIdentity] = parent
	}

	return tree
}

func (t *ProcessTree) Process(
	identity core.ProcessIdentity,
) (core.Process, bool) {
	process, exists := t.processes[identity]
	return process, exists
}

func (t *ProcessTree) Parent(
	identity core.ProcessIdentity,
) (core.Process, bool) {
	parent, exists := t.parents[identity]
	return parent, exists
}

func (t *ProcessTree) Children(
	identity core.ProcessIdentity,
) []core.Process {
	return t.children[identity]
}

func (t *ProcessTree) Processes() []core.Process {
	processes := make([]core.Process, 0, len(t.processes))

	for _, process := range t.processes {
		processes = append(processes, process)
	}

	return processes
}
