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
