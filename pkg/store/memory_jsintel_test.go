package store

import (
	"testing"

	"github.com/dinosn/leaklens/pkg/jsintel"
	"github.com/dinosn/leaklens/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestMemoryJSIntelFindingRoundTripAndDeduplication(t *testing.T) {
	store := NewMemory()
	blobID := types.ComputeBlobID([]byte("api.uat.example.test"))
	record := jsintel.NewStoredFinding(blobID, jsintel.Finding{
		Category:    jsintel.CategorySubdomain,
		Value:       "api.uat.example.test",
		Confidence:  "info",
		Environment: "uat",
		Line:        1,
		Column:      1,
	})

	require.NoError(t, store.AddJSIntelFinding(record))
	record.Confidence = "medium"
	require.NoError(t, store.AddJSIntelFinding(record))

	findings, err := store.GetJSIntelFindings()
	require.NoError(t, err)
	require.Len(t, findings, 1)
	require.Equal(t, "medium", findings[0].Confidence)
	require.Equal(t, "uat", findings[0].Environment)
}
