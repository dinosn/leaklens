package jsintel

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"sort"

	"github.com/dinosn/leaklens/pkg/types"
)

// StoredFinding ties a JS-intelligence artifact to the scanned blob that
// produced it. It is intentionally separate from rule-based secret findings.
type StoredFinding struct {
	ID     string       `json:"id"`
	BlobID types.BlobID `json:"blob_id"`
	Finding
}

// NewStoredFinding creates a stable, content-addressed JS-intelligence record.
func NewStoredFinding(blobID types.BlobID, finding Finding) *StoredFinding {
	record := &StoredFinding{BlobID: blobID, Finding: finding}
	record.ID = ComputeStoredFindingID(blobID, finding)
	return record
}

// ComputeStoredFindingID identifies one artifact occurrence without including
// mutable classification fields such as confidence, active status, or tags.
func ComputeStoredFindingID(blobID types.BlobID, finding Finding) string {
	payload, _ := json.Marshal(struct {
		BlobID   string   `json:"blob_id"`
		Category Category `json:"category"`
		Value    string   `json:"value"`
		Detail   string   `json:"detail"`
		Method   string   `json:"method"`
		Line     int      `json:"line"`
		Column   int      `json:"column"`
	}{
		BlobID:   blobID.Hex(),
		Category: finding.Category,
		Value:    finding.Value,
		Detail:   finding.Detail,
		Method:   finding.Method,
		Line:     finding.Line,
		Column:   finding.Column,
	})
	sum := sha1.Sum(payload)
	return hex.EncodeToString(sum[:])
}

// SortStoredFindings makes persisted and reported output deterministic.
func SortStoredFindings(findings []*StoredFinding) {
	sort.SliceStable(findings, func(i, j int) bool {
		left, right := findings[i], findings[j]
		if left.BlobID != right.BlobID {
			return left.BlobID.Hex() < right.BlobID.Hex()
		}
		if left.Category != right.Category {
			return left.Category < right.Category
		}
		if left.Value != right.Value {
			return left.Value < right.Value
		}
		if left.Line != right.Line {
			return left.Line < right.Line
		}
		if left.Column != right.Column {
			return left.Column < right.Column
		}
		return left.ID < right.ID
	})
}
