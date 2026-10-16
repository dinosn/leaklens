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

func TestLikelyAPISecretCandidate(t *testing.T) {
	testCases := []struct {
		name  string
		value string
		want  bool
	}{
		{name: "eight character mixed secret", value: "Q7vN2mX9", want: true},
		{name: "seven character secret", value: "Q7vN2mX", want: false},
		{name: "letters only", value: "abcdefgh", want: false},
		{name: "digits only", value: "12345678", want: false},
		{name: "low diversity", value: "A1A1A1A1", want: false},
		{name: "obvious placeholder", value: "YOUR_API_SECRET_123", want: false},
		{name: "test placeholder", value: "test-api-secret-123", want: false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, isLikelyAPISecretCandidate(tc.value))
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
			assert.True(t, shouldSuppressMatch(&types.Rule{ID: ruleID}, match, nil))

			match.NamedGroups["token"] = []byte("4f9A2b7C8d1E6g")
			assert.False(t, shouldSuppressMatch(&types.Rule{ID: ruleID}, match, nil))
		})
	}
}

func TestDataDrivenRulePolicies(t *testing.T) {
	minDigits := 2
	minUppercase := 1
	minSpecial := 2
	customSpecial := ":-"

	testCases := []struct {
		name  string
		rule  *types.Rule
		match *types.Match
		want  bool
	}{
		{
			name: "entropy rejects low-complexity candidate",
			rule: &types.Rule{MinEntropy: 3.0},
			match: &types.Match{
				SecretValue: []byte("fooProd"),
				Groups:      [][]byte{[]byte("fooProd")},
			},
			want: true,
		},
		{
			name: "camel-case literal is not a global placeholder",
			rule: &types.Rule{},
			match: &types.Match{
				SecretValue: []byte("fooProd"),
				Groups:      [][]byte{[]byte("fooProd")},
			},
			want: false,
		},
		{
			name: "exact environment template is suppressed",
			rule: &types.Rule{},
			match: &types.Match{
				SecretValue: []byte("${CLIENT_SECRET}"),
				Groups:      [][]byte{[]byte("${CLIENT_SECRET}")},
			},
			want: true,
		},
		{
			name: "exact mustache template is suppressed",
			rule: &types.Rule{},
			match: &types.Match{
				SecretValue: []byte("{{ CLIENT_SECRET }}"),
				Groups:      [][]byte{[]byte("{{ CLIENT_SECRET }}")},
			},
			want: true,
		},
		{
			name: "exact ERB template is suppressed",
			rule: &types.Rule{},
			match: &types.Match{
				SecretValue: []byte(`<%= ENV["CLIENT_SECRET"] %>`),
				Groups:      [][]byte{[]byte(`<%= ENV["CLIENT_SECRET"] %>`)},
			},
			want: true,
		},
		{
			name: "character requirements reject candidate",
			rule: &types.Rule{PatternRequirements: &types.PatternRequirements{
				MinDigits:    &minDigits,
				MinUppercase: &minUppercase,
			}},
			match: &types.Match{
				SecretValue: []byte("abcdef1"),
				Groups:      [][]byte{[]byte("abcdef1")},
			},
			want: true,
		},
		{
			name: "character requirements accept candidate",
			rule: &types.Rule{PatternRequirements: &types.PatternRequirements{
				MinDigits:    &minDigits,
				MinUppercase: &minUppercase,
			}},
			match: &types.Match{
				SecretValue: []byte("Abcdef12"),
				Groups:      [][]byte{[]byte("Abcdef12")},
			},
			want: false,
		},
		{
			name: "custom special-character set rejects candidate",
			rule: &types.Rule{PatternRequirements: &types.PatternRequirements{
				MinSpecialChars: &minSpecial,
				SpecialChars:    &customSpecial,
			}},
			match: &types.Match{
				SecretValue: []byte("abc:def"),
				Groups:      [][]byte{[]byte("abc:def")},
			},
			want: true,
		},
		{
			name: "custom special-character set accepts candidate",
			rule: &types.Rule{PatternRequirements: &types.PatternRequirements{
				MinSpecialChars: &minSpecial,
				SpecialChars:    &customSpecial,
			}},
			match: &types.Match{
				SecretValue: []byte("abc:-def"),
				Groups:      [][]byte{[]byte("abc:-def")},
			},
			want: false,
		},
		{
			name: "ignored substring uses full match for named pattern",
			rule: &types.Rule{PatternRequirements: &types.PatternRequirements{
				IgnoreIfContains: []string{"dummy"},
			}},
			match: &types.Match{
				SecretValue:    []byte("A1b2C3d4"),
				HasNamedGroups: true,
				NamedGroups:    map[string][]byte{"key": []byte("A1b2C3d4")},
				Snippet:        types.Snippet{Matching: []byte("dummy=A1b2C3d4")},
			},
			want: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, shouldSuppressMatch(tc.rule, tc.match, nil))
		})
	}
}

func TestBuiltInRuleQualityPolicies(t *testing.T) {
	t.Run("Azure dummy values", func(t *testing.T) {
		rules := loadMatcherRulesByID(t, "np.azure.5")
		rule := rules[0]
		m, err := NewPortableRegexp(rules, 0)
		require.NoError(t, err)
		defer m.Close()

		matches, err := m.Match([]byte(matcherExampleContaining(t, rule.NegativeExamples, "00000000")))
		require.NoError(t, err)
		require.Empty(t, matches)

		matches, err = m.Match([]byte(rule.Examples[0]))
		require.NoError(t, err)
		require.Len(t, matches, 1)

		matches, err = m.Match([]byte("// " + rule.Examples[0]))
		require.NoError(t, err)
		require.Len(t, matches, 1, "commented credentials can still be live and must not be suppressed generically")
	})

	t.Run("Zuplo checksum", func(t *testing.T) {
		rules := loadMatcherRulesByID(t, "kingfisher.zuplo.1")
		rule := rules[0]
		m, err := NewPortableRegexp(rules, 0)
		require.NoError(t, err)
		defer m.Close()

		matches, err := m.Match([]byte(rule.Examples[0]))
		require.NoError(t, err)
		require.Len(t, matches, 1)

		matches, err = m.Match([]byte(matcherExampleWithChangedLastByte(t, rule.Examples[0])))
		require.NoError(t, err)
		require.Empty(t, matches)
	})

	t.Run("Confluent checksum", func(t *testing.T) {
		rules := loadMatcherRulesByID(t, "kingfisher.confluent.3")
		rule := rules[0]
		m, err := NewPortableRegexp(rules, 0)
		require.NoError(t, err)
		defer m.Close()

		matches, err := m.Match([]byte(rule.Examples[0]))
		require.NoError(t, err)
		require.Len(t, matches, 1)

		matches, err = m.Match([]byte(matcherExampleWithChangedLastByte(t, rule.Examples[0])))
		require.NoError(t, err)
		require.Empty(t, matches)
	})
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

func matcherRuleByID(t *testing.T, rules []*types.Rule, ruleID string) *types.Rule {
	t.Helper()
	for _, rule := range rules {
		if rule.ID == ruleID {
			return rule
		}
	}
	t.Fatalf("missing matcher rule %s", ruleID)
	return nil
}

func matcherExampleContaining(t *testing.T, examples []string, needle string) string {
	t.Helper()
	for _, example := range examples {
		if strings.Contains(example, needle) {
			return example
		}
	}
	t.Fatalf("missing matcher example containing %q", needle)
	return ""
}

func matcherExampleWithChangedLastByte(t *testing.T, example string) string {
	t.Helper()
	require.NotEmpty(t, example)
	changed := []byte(example)
	if changed[len(changed)-1] == '0' {
		changed[len(changed)-1] = '1'
	} else {
		changed[len(changed)-1] = '0'
	}
	return string(changed)
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
