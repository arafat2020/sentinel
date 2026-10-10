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

// maxDescendantVisits bounds one walk down the tree, however deep and wide
// the tree is.
const maxDescendantVisits = 4096

// walkDescendants visits the descendants of parent, down to maxDepth
// generations, until visit returns false. It reports whether the walk was
// cut short by maxDescendantVisits, in which case some descendants were not
// visited.
//
// known, if not nil, says whether a process may be counted on: the walk does
// not visit, or pass through, one that it rejects. Ancestry is only as good
// as every link in it, in whichever direction it is followed.
func walkDescendants(
	t *topology,
	parent core.ProcessIdentity,
	maxDepth int,
	known func(core.ProcessIdentity) bool,
	visit func(core.ProcessIdentity) bool,
) (truncated bool) {
	visited := 0

	var descend func(identity core.ProcessIdentity, depth int) bool
	descend = func(identity core.ProcessIdentity, depth int) bool {
		for child := range t.children[identity] {
			if visited >= maxDescendantVisits {
				truncated = true
				return false
			}
			visited++

			if known != nil && !known(child) {
				continue
			}
			if !visit(child) {
				return false
			}
			if depth < maxDepth && !descend(child, depth+1) {
				return false
			}
		}
		return true
	}

	descend(parent, 1)

	return truncated
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
