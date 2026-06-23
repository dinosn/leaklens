//go:build !wasm && cgo && vectorscan

package matcher

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVectorscanGenericPasswordUIPromptSuppression(t *testing.T) {
	rules := loadGenericPasswordRules(t)

	m, err := NewVectorscan(rules, 0)
	require.NoError(t, err)
	defer m.Close()

	content := []byte(`const Lm={Password:"请输入密码！"}; const cfg={Password:"P@ssw0rd123!"};`)
	matches, err := m.Match(content)
	require.NoError(t, err)
	assert.Equal(t, []string{"P@ssw0rd123!"}, matchGroupValues(matches))
}
