package rule

import (
	"testing"

	"github.com/dinosn/leaklens/pkg/matcher"
	"github.com/dinosn/leaklens/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestBaiduMapsAPIKeyRule(t *testing.T) {
	rule := loadBuiltinRuleByID(t, "leaklens.baidu.maps.1")
	require.Contains(t, rule.Pattern, "(?P<key>")

	m, err := matcher.NewPortableRegexp([]*types.Rule{rule}, 0)
	require.NoError(t, err)

	for _, example := range rule.Examples {
		t.Run("positive", func(t *testing.T) {
			matches, err := m.Match([]byte(example))
			require.NoError(t, err)
			require.Len(t, matches, 1, "example should match: %s", example)
			require.NotEmpty(t, matches[0].NamedGroups["key"], "key capture should be populated")
		})
	}

	for _, example := range rule.NegativeExamples {
		t.Run("negative", func(t *testing.T) {
			matches, err := m.Match([]byte(example))
			require.NoError(t, err)
			require.Empty(t, matches, "negative example should not match: %s", example)
		})
	}
}
