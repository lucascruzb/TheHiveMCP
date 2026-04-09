package search

import (
	"testing"

	"github.com/StrangeBeeCorp/TheHiveMCP/internal/types"
	"github.com/stretchr/testify/assert"
)

func TestGetExcludedFields_IdNeverExcluded(t *testing.T) {
	tool := &SearchTool{}

	entityTypes := []string{
		types.EntityTypeAlert,
		types.EntityTypeCase,
		types.EntityTypeTask,
		types.EntityTypeObservable,
		types.EntityTypeProcedure,
		types.EntityTypePattern,
		types.EntityTypeCaseTemplate,
		types.EntityTypePage,
	}

	for _, entityType := range entityTypes {
		t.Run(entityType, func(t *testing.T) {
			// When keptColumns does NOT include _id, it should still not be excluded
			excluded := tool.getExcludedFields(entityType, []string{"title"}, nil)
			assert.NotContains(t, excluded, "_id",
				"_id must never be excluded from search results for entity type %s", entityType)
		})
	}
}

func TestGetExcludedFields_IdNotExcludedWithExtraColumns(t *testing.T) {
	tool := &SearchTool{}

	// Simulate the bug scenario: extra-columns specified without _id,
	// and additional-queries would need _id
	keptColumns := []string{"title", "description", "source", "tags", "severity"}
	excluded := tool.getExcludedFields(types.EntityTypeAlert, keptColumns, nil)

	assert.NotContains(t, excluded, "_id",
		"_id must never be excluded even when not in keptColumns")
}

func TestGetExcludedFields_ExtraDataPreserved(t *testing.T) {
	tool := &SearchTool{}

	// extraData should not be excluded when extraData list is non-empty
	excluded := tool.getExcludedFields(types.EntityTypeCase, []string{"title"}, []string{"someField"})
	assert.NotContains(t, excluded, "extraData",
		"extraData should not be excluded when extraData list is non-empty")
}
