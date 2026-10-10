package correlation

import "github.com/arafat2020/sentinel/internal/core"

// topology is the parent/child structure of the known processes. A process
// has at most one parent, so the same pair can never be linked twice.
type topology struct {
	parent   map[core.ProcessIdentity]core.ProcessIdentity
	children map[core.ProcessIdentity]map[core.ProcessIdentity]struct{}
}

func newTopology() *topology {
	return &topology{
		parent:   make(map[core.ProcessIdentity]core.ProcessIdentity),
		children: make(map[core.ProcessIdentity]map[core.ProcessIdentity]struct{}),
	}
}

// link makes parent the parent of child, replacing any previous parent.
func (t *topology) link(parent, child core.ProcessIdentity) {
	t.unlink(child)

	t.parent[child] = parent

	siblings := t.children[parent]
	if siblings == nil {
		siblings = make(map[core.ProcessIdentity]struct{})
		t.children[parent] = siblings
	}
	siblings[child] = struct{}{}
}

// unlink detaches child from its parent, if it has one.
func (t *topology) unlink(child core.ProcessIdentity) {
	parent, ok := t.parent[child]
	if !ok {
		return
	}

	delete(t.parent, child)

	siblings := t.children[parent]
	delete(siblings, child)
	if len(siblings) == 0 {
		delete(t.children, parent)
	}
}

// remove deletes a process from the structure: its link to its parent and
// its links to its children.
func (t *topology) remove(identity core.ProcessIdentity) {
	t.unlink(identity)

	for child := range t.children[identity] {
		delete(t.parent, child)
	}
	delete(t.children, identity)
}
