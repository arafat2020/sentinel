package correlation

import "github.com/arafat2020/sentinel/internal/core"

type RelationshipType string

const (
	// RelationshipSpawned holds when the parent directly spawned the child.
	RelationshipSpawned RelationshipType = "SPAWNED"
	// RelationshipDescendant holds when the child is a descendant of the
	// parent within a number of generations: its child, grandchild and so
	// on. SPAWNED is the one-generation case.
	RelationshipDescendant RelationshipType = "DESCENDANT"
)

const (
	// DefaultMaxDepth is how many generations a DESCENDANT relationship
	// spans when the pattern does not say.
	DefaultMaxDepth = 5
	// MaxDepthLimit is the most generations a DESCENDANT relationship may
	// span.
	MaxDepthLimit = 16
)

type ProcessRelationship struct {
	Type   RelationshipType
	Parent core.Process
	Child  core.Process
}

func NewProcessRelationship(
	parent core.Process,
	child core.Process,
) ProcessRelationship {
	return ProcessRelationship{
		Type:   RelationshipSpawned,
		Parent: parent,
		Child:  child,
	}
}
