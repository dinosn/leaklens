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
		{
			name: "translated input type label",
			content: `const labels={inputType:{color:"Color",date:"Date",email:"Email",month:"Month",` +
				`number:"Number",password:"LocalizedPassLabel",range:"Range",tel:"Phone",text:"Text",` +
				`time:"Time",url:"URL",week:"Week"}};`,
			wantValues: []string{},
		},
		{
			name:       "alphabetic password outside input type catalog still reports",
			content:    `const cfg={username:"operator",password:"LocalizedPassLabel",host:"db.example.test"};`,
			wantValues: []string{"LocalizedPassLabel"},
		},
		{
			name:       "weak password matching property name still reports",
			content:    `const cfg={username:"operator",password:"password"};`,
			wantValues: []string{"password"},
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

func TestLinkedInAccessTokenContextSuppression(t *testing.T) {
	const token = "AQ0123456789abcdefghijklmnopqrstuv"
	rules := loadMatcherRulesByID(t, "np.linkedin.3")

	m, err := NewPortableRegexp(rules, 0)
	require.NoError(t, err)
	defer m.Close()

	testCases := []struct {
		name    string
		content string
		want    int
	}{
		{
			name:    "base64 asset segment is not a LinkedIn token",
			content: `const image="data:image/png;base64,abc/` + token + `/def";`,
			want:    0,
		},
		{
			name:    "unlabeled application string is not provider attribution",
			content: `const generated="` + token + `";`,
			want:    0,
		},
		{
			name:    "provider-labeled token reports",
			content: `const LINKEDIN_ACCESS_TOKEN="` + token + `";`,
			want:    1,
		},
		{
			name:    "bearer token reports",
			content: `const headers={Authorization:"Bearer ` + token + `"};`,
			want:    1,
		},
		{
			name:    "bare token line reports",
			content: token + "\n",
			want:    1,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			matches, err := m.Match([]byte(tc.content))
			require.NoError(t, err)
			assert.Len(t, matches, tc.want)
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

func TestLikelyOpaqueSecretCandidate(t *testing.T) {
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
			assert.Equal(t, tc.want, isLikelyOpaqueSecretCandidate(tc.value))
		})
	}
}

func TestShouldSuppressOpaqueSecretUsesNamedCapture(t *testing.T) {
	for _, ruleID := range []string{
		"leaklens.http.query-secret.1",
		"leaklens.http.api-key-header.1",
	} {
		t.Run(ruleID, func(t *testing.T) {
			match := &types.Match{
				RuleID:      ruleID,
				NamedGroups: map[string][]byte{"token": []byte("example123456")},
			}
			assert.True(t, shouldSuppressMatch(match, nil))

			match.NamedGroups["token"] = []byte("4f9A2b7C8d1E6g")
			assert.False(t, shouldSuppressMatch(match, nil))
		})
	}
}

func loadGenericPasswordRules(t *testing.T) []*types.Rule {
	return loadMatcherRulesByID(t, "np.generic.5", "np.generic.6")
}

func loadMatcherRulesByID(t *testing.T, ruleIDs ...string) []*types.Rule {
	t.Helper()

	loader := rule.NewLoader()
	rules, err := loader.LoadBuiltinRules()
	require.NoError(t, err)

	wanted := make(map[string]bool, len(ruleIDs))
	for _, ruleID := range ruleIDs {
		wanted[ruleID] = true
	}

	filtered := make([]*types.Rule, 0, len(wanted))
	for _, candidate := range rules {
		if wanted[candidate.ID] {
			filtered = append(filtered, candidate)
			delete(wanted, candidate.ID)
		}
	}

	require.Empty(t, wanted, "missing built-in matcher rules")
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
