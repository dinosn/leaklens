//go:build !wasm && cgo && vectorscan

package matcher

import (
	"strings"
	"testing"

	"github.com/dinosn/leaklens/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVectorscanGenericPasswordUIPromptSuppression(t *testing.T) {
	rules := loadGenericPasswordRules(t)

	m, err := NewVectorscan(rules, 0)
	require.NoError(t, err)
	defer m.Close()

	content := []byte(`
		const Lm={Password:"请输入密码！"};
		const labels={inputType:{color:"Color",date:"Date",email:"Email",month:"Month",
			number:"Number",password:"LocalizedPassLabel",range:"Range",tel:"Phone",text:"Text",
			time:"Time",url:"URL",week:"Week"}};
		const cfg={Password:"P@ssw0rd123!"};
	`)
	matches, err := m.Match(content)
	require.NoError(t, err)
	assert.Equal(t, []string{"P@ssw0rd123!"}, matchGroupValues(matches))
}

func TestVectorscanLinkedInAccessTokenContextSuppression(t *testing.T) {
	const token = "AQ0123456789abcdefghijklmnopqrstuv"
	rules := loadMatcherRulesByID(t, "np.linkedin.3")

	m, err := NewVectorscan(rules, 0)
	require.NoError(t, err)
	defer m.Close()

	content := []byte(`const image="data:image/png;base64,abc/` + token + `/def";` +
		`const LINKEDIN_ACCESS_TOKEN="` + token + `";`)
	matches, err := m.Match(content)
	require.NoError(t, err)
	require.Len(t, matches, 1)
	assert.Equal(t, token, string(matches[0].NamedGroups["access_token"]))
}

func TestVectorscanDataDrivenRulePolicies(t *testing.T) {
	rules := loadMatcherRulesByID(t, "np.azure.5", "kingfisher.zuplo.1")
	azureRule := matcherRuleByID(t, rules, "np.azure.5")
	zuploRule := matcherRuleByID(t, rules, "kingfisher.zuplo.1")
	m, err := NewVectorscan(rules, 0)
	require.NoError(t, err)
	defer m.Close()

	content := []byte(strings.Join([]string{
		matcherExampleContaining(t, azureRule.NegativeExamples, "00000000"),
		azureRule.Examples[0],
		zuploRule.Examples[0],
		matcherExampleWithChangedLastByte(t, zuploRule.Examples[0]),
	}, "\n"))
	matches, err := m.Match(content)
	require.NoError(t, err)
	require.Len(t, matches, 2)

	byRule := make(map[string]*types.Match, len(matches))
	for _, match := range matches {
		byRule[match.RuleID] = match
	}
	require.Contains(t, byRule, "np.azure.5")
	require.Contains(t, byRule, "kingfisher.zuplo.1")
}
