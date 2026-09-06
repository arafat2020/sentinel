package correlation

import "github.com/arafat2020/sentinel/internal/core"

type RelationshipType string

const (
	RelationshipSpawned RelationshipType = "SPAWNED"
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
