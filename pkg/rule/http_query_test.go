package rule

import (
	"strings"
	"testing"

	"github.com/dinosn/leaklens/pkg/matcher"
	"github.com/dinosn/leaklens/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestHTTPQuerySecretCandidate(t *testing.T) {
	rule := loadBuiltinRuleByID(t, "leaklens.http.query-secret.1")
	require.NoError(t, ValidateRule(rule))

	m, err := matcher.NewPortableRegexp([]*types.Rule{rule}, 0)
	require.NoError(t, err)
	defer m.Close()

	testCases := []struct {
		name      string
		content   string
		wantToken string
	}{
		{
			name:      "short opaque query token",
			content:   `fetch("https://geo.example.test/json?token=4f9A2b7C8d1E6g")`,
			wantToken: "4f9A2b7C8d1E6g",
		},
		{
			name:      "later access token parameter",
			content:   `fetch("https://api.example.test/data?format=json&access_token=N7qP2mX9vR4sL8&lang=en")`,
			wantToken: "N7qP2mX9vR4sL8",
		},
		{
			name:      "camel case API key parameter",
			content:   `fetch("https://api.example.test/data?apiKey=Q7xV2mN9pR4sL8")`,
			wantToken: "Q7xV2mN9pR4sL8",
		},
		{
			name:      "hyphenated auth token parameter",
			content:   `fetch("https://api.example.test/data?auth-token=Z8rM3pQ6vN1xK5")`,
			wantToken: "Z8rM3pQ6vN1xK5",
		},
		{
			name:      "padded URL safe token",
			content:   `fetch("https://api.example.test/data?clientSecret=Q7xV2mN9pR4sL8==")`,
			wantToken: "Q7xV2mN9pR4sL8==",
		},
		{name: "relative URL", content: `fetch("/json?token=4f9A2b7C8d1E6g")`},
		{name: "fragment token", content: `fetch("https://geo.example.test/json#token=4f9A2b7C8d1E6g")`},
		{name: "short value", content: `fetch("https://geo.example.test/json?token=short1")`},
		{name: "letters only", content: `fetch("https://geo.example.test/json?token=abcdefghijklmn")`},
		{name: "digits only", content: `fetch("https://geo.example.test/json?token=12345678901234")`},
		{name: "low diversity", content: `fetch("https://geo.example.test/json?token=a1a1a1a1a1a1a1")`},
		{name: "placeholder", content: `fetch("https://geo.example.test/json?token=example123456")`},
		{name: "page token", content: `fetch("https://geo.example.test/json?page_token=4f9A2b7C8d1E6g")`},
		{name: "runtime interpolation", content: `fetch("https://geo.example.test/json?token=${TOKEN}")`},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			matches, err := m.Match([]byte(tc.content))
			require.NoError(t, err)
			if tc.wantToken == "" {
				require.Empty(t, matches)
				return
			}
			require.Len(t, matches, 1)
			require.Equal(t, tc.wantToken, string(matches[0].NamedGroups["token"]))
		})
	}
}

func TestHTTPQuerySecretCandidateParallel(t *testing.T) {
	rule := loadBuiltinRuleByID(t, "leaklens.http.query-secret.1")
	m, err := matcher.NewPortableRegexp([]*types.Rule{rule}, 0)
	require.NoError(t, err)
	defer m.Close()

	content := strings.Repeat(`const next="/items?page_token=continuation";`+"\n", 300)
	content += `fetch("https://geo.example.test/json?token=4f9A2b7C8d1E6g")`
	matches, err := m.Match([]byte(content))
	require.NoError(t, err)
	require.Len(t, matches, 1)
	require.Equal(t, "4f9A2b7C8d1E6g", string(matches[0].NamedGroups["token"]))
}
