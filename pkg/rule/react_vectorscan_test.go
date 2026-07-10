//go:build !wasm && cgo && vectorscan

package rule

import (
	"testing"

	"github.com/dinosn/leaklens/pkg/matcher"
	"github.com/dinosn/leaklens/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestReactAppCompiledPasswordVectorscan(t *testing.T) {
	rule := loadBuiltinRuleByID(t, "np.reactapp.2")
	m, err := matcher.NewVectorscan([]*types.Rule{rule}, 0)
	require.NoError(t, err)
	defer m.Close()

	matches, err := m.Match([]byte(`const env={REACT_APP_DEMO_PASSWORD:"S7nthetic/value-42"};`))
	require.NoError(t, err)
	require.Len(t, matches, 1)
	require.Equal(t, "S7nthetic/value-42", string(matches[0].Groups[0]))
}
