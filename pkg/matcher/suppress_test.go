//go:build !wasm

package matcher

import (
	"strings"
	"testing"

	"github.com/dinosn/leaklens/pkg/rule"
	"github.com/dinosn/leaklens/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenericPasswordUIPromptSuppression(t *testing.T) {
	rules := loadGenericPasswordRules(t)

	m, err := NewPortableRegexp(rules, 0)
	require.NoError(t, err)
	defer m.Close()

	testCases := []struct {
		name       string
		content    string
		wantValues []string
	}{
		{
			name:       "double quoted Chinese password prompt",
			content:    `const Lm={UserName:"请输入用户名！",Password:"请输入密码！",Email:"请输入邮箱！"};`,
			wantValues: []string{},
		},
		{
			name:       "single quoted Chinese password prompt",
			content:    `const Lm={Password:'请输入密码！'};`,
			wantValues: []string{},
		},
		{
			name:       "unicode escaped Chinese password prompt",
			content:    `const Lm={Password:"\u8bf7\u8f93\u5165\u5bc6\u7801\uff01"};`,
			wantValues: []string{},
		},
		{
			name:       "real-looking double quoted password still reports",
			content:    `const cfg={Password:"P@ssw0rd123!"};`,
			wantValues: []string{"P@ssw0rd123!"},
		},
		{
			name:       "real-looking single quoted password still reports",
			content:    `const cfg={Password:'4ian1234'};`,
			wantValues: []string{"4ian1234"},
		},
		{
			name:       "Chinese password-like value without prompt marker still reports",
			content:    `const cfg={Password:"蓝色密码123"};`,
			wantValues: []string{"蓝色密码123"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			matches, err := m.Match([]byte(tc.content))
			require.NoError(t, err)
			assert.Equal(t, tc.wantValues, matchGroupValues(matches))
		})
	}
}

func TestGenericPasswordUIPromptSuppressionParallel(t *testing.T) {
	rules := loadGenericPasswordRules(t)

	m, err := NewPortableRegexp(rules, 0)
	require.NoError(t, err)
	defer m.Close()

	var sb strings.Builder
	for sb.Len() < parallelThreshold+100 {
		sb.WriteString(`const Lm={Password:"请输入密码！"};` + "\n")
	}
	sb.WriteString(`const cfg={Password:"P@ssw0rd123!"};`)

	matches, err := m.Match([]byte(sb.String()))
	require.NoError(t, err)
	assert.Equal(t, []string{"P@ssw0rd123!"}, matchGroupValues(matches))
}

func TestHTTPQuerySecretSuppression(t *testing.T) {
	testCases := []struct {
		name  string
		value string
		want  bool
	}{
		{name: "mixed opaque token", value: "4f9A2b7C8d1E6g", want: true},
		{name: "URL safe token", value: "N7qP2mX9vR4sL8-za_", want: true},
		{name: "short token", value: "a1b2c3", want: false},
		{name: "letters only", value: "abcdefghijklmn", want: false},
		{name: "digits only", value: "12345678901234", want: false},
		{name: "low diversity", value: "a1a1a1a1a1a1a1", want: false},
		{name: "example placeholder", value: "example123456", want: false},
		{name: "your token placeholder", value: "YOUR_API_TOKEN_12345", want: false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, isLikelyHTTPQuerySecret(tc.value))
		})
	}
}

func TestShouldSuppressHTTPQuerySecretUsesNamedCapture(t *testing.T) {
	match := &types.Match{
		RuleID:      "leaklens.http.query-secret.1",
		NamedGroups: map[string][]byte{"token": []byte("example123456")},
	}
	assert.True(t, shouldSuppressMatch(match))

	match.NamedGroups["token"] = []byte("4f9A2b7C8d1E6g")
	assert.False(t, shouldSuppressMatch(match))
}

func loadGenericPasswordRules(t *testing.T) []*types.Rule {
	t.Helper()

	loader := rule.NewLoader()
	rules, err := loader.LoadBuiltinRules()
	require.NoError(t, err)

	wanted := map[string]bool{
		"np.generic.5": true,
		"np.generic.6": true,
	}

	filtered := make([]*types.Rule, 0, len(wanted))
	for _, candidate := range rules {
		if wanted[candidate.ID] {
			filtered = append(filtered, candidate)
			delete(wanted, candidate.ID)
		}
	}

	require.Empty(t, wanted, "missing built-in generic password rules")
	return filtered
}

func matchGroupValues(matches []*types.Match) []string {
	values := make([]string, 0, len(matches))
	for _, match := range matches {
		if len(match.Groups) == 0 {
			continue
		}
		values = append(values, string(match.Groups[0]))
	}
	return values
}
