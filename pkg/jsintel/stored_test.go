package jsintel

import (
	"testing"

	"github.com/dinosn/leaklens/pkg/types"
)

func TestStoredFindingIDIsStableAndIgnoresMutableClassification(t *testing.T) {
	blobID := types.ComputeBlobID([]byte("const endpoint = 'api.uat.example.test';"))
	finding := Finding{
		Category:    CategorySubdomain,
		Value:       "api.uat.example.test",
		Confidence:  "info",
		Environment: "uat",
		Line:        1,
		Column:      19,
	}

	first := NewStoredFinding(blobID, finding)
	finding.Confidence = "medium"
	finding.Environment = "test"
	finding.Active = true
	second := NewStoredFinding(blobID, finding)

	if first.ID != second.ID {
		t.Fatalf("mutable classification changed stable ID: %s != %s", first.ID, second.ID)
	}
	if first.BlobID != blobID {
		t.Fatalf("unexpected blob ID: %s", first.BlobID)
	}
}
