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

func TestHTTPAPIKeyHeaderCandidateVectorscan(t *testing.T) {
	rule := loadBuiltinRuleByID(t, "leaklens.http.api-key-header.1")
	m, err := matcher.NewVectorscan([]*types.Rule{rule}, 0)
	require.NoError(t, err)
	defer m.Close()

	content := []byte(`
		const ignored={"x-api-key":"YOUR_API_KEY_HERE_1234567890"};
		const detected={"x-api-key":"".concat("A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0")};
	`)
	matches, err := m.Match(content)
	require.NoError(t, err)
	require.Len(t, matches, 1)
	require.Equal(t, "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0", string(matches[0].NamedGroups["token"]))
}
