//go:build !wasm && cgo && vectorscan

package rule

import (
	"testing"

	"github.com/dinosn/leaklens/pkg/matcher"
	"github.com/dinosn/leaklens/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestHTTPQuerySecretCandidateVectorscan(t *testing.T) {
	rule := loadBuiltinRuleByID(t, "leaklens.http.query-secret.1")
	m, err := matcher.NewVectorscan([]*types.Rule{rule}, 0)
	require.NoError(t, err)
	defer m.Close()

	content := []byte(`
		fetch("https://geo.example.test/json?token=example123456");
		fetch("https://geo.example.test/json?token=4f9A2b7C8d1E6g");
	`)
	matches, err := m.Match(content)
	require.NoError(t, err)
	require.Len(t, matches, 1)
	require.Equal(t, "4f9A2b7C8d1E6g", string(matches[0].NamedGroups["token"]))
}
