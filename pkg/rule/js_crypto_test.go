package rule

import (
	"testing"

	"github.com/dinosn/leaklens/pkg/matcher"
	"github.com/dinosn/leaklens/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestClientSideAESKeyCandidate(t *testing.T) {
	rule := loadBuiltinRuleByID(t, "leaklens.js.crypto.1")
	m, err := matcher.NewPortableRegexp([]*types.Rule{rule}, 0)
	require.NoError(t, err)

	tests := []struct {
		name    string
		content string
		want    bool
	}{
		{
			name:    "observed g_ac convention",
			content: `var g_ac = "A1!bcdefghijklmn";`,
			want:    true,
		},
		{
			name:    "semantic aes key",
			content: `const aesKey = "a1bcdefghijklmno";`,
			want:    true,
		},
		{
			name:    "semantic crypto object property",
			content: `{"cryptoSecret": "a1bcdefghijklmno"}`,
			want:    true,
		},
		{
			name:    "g_ac low complexity",
			content: `var g_ac = "abcdefghijklmnop";`,
			want:    false,
		},
		{
			name:    "no crypto variable context",
			content: `var displayName = "A1!bcdefghijklmn";`,
			want:    false,
		},
		{
			name:    "generic access key does not imply AES",
			content: `const accessKey = "a1bcdefghijklmno";`,
			want:    false,
		},
		{
			name:    "wrong key length",
			content: `const aesKey = "short";`,
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches, err := m.Match([]byte(tt.content))
			require.NoError(t, err)
			if tt.want {
				require.Len(t, matches, 1)
				require.Equal(t, "leaklens.js.crypto.1", matches[0].RuleID)
				return
			}
			require.Empty(t, matches)
		})
	}
}

func loadBuiltinRuleByID(t *testing.T, id string) *types.Rule {
	t.Helper()
	loader := NewLoader()
	rules, err := loader.LoadBuiltinRules()
	require.NoError(t, err)
	for _, rule := range rules {
		if rule.ID == id {
			return rule
		}
	}
	t.Fatalf("rule %s not found", id)
	return nil
}
