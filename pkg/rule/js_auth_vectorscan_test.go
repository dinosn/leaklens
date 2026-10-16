//go:build !wasm && cgo && vectorscan

package rule

import (
	"testing"

	"github.com/dinosn/leaklens/pkg/matcher"
	"github.com/dinosn/leaklens/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestJavaScriptClientCredentialsVectorscan(t *testing.T) {
	rules := []*types.Rule{
		loadBuiltinRuleByID(t, "leaklens.js.client-secret.1"),
		loadBuiltinRuleByID(t, "leaklens.js.api-secret.1"),
		loadBuiltinRuleByID(t, "leaklens.js.basic-auth-flow.1"),
	}

	m, err := matcher.NewVectorscan(rules, 0)
	require.NoError(t, err)
	defer m.Close()

	content := []byte(`
		const ignored={clientSecret:"YOUR_CLIENT_SECRET_123456"};
		const config={clientId:"web_portal",clientSecret:"Q7vN2mX9pR4sL8kD6wT3"};
		const apiConfig={apiUrl:"https://api.example.test/",apiSecret:"Z8rM3pQ6"};
		const headers={"Authorization":"Basic "+Demo.lib.Base64.encode(Demo.Config.clientId+":"+Demo.Config.clientSecret)};
	`)
	matches, err := m.Match(content)
	require.NoError(t, err)
	require.Len(t, matches, 3)

	byRule := make(map[string]*types.Match, len(matches))
	for _, match := range matches {
		byRule[match.RuleID] = match
	}
	require.Equal(t, "Q7vN2mX9pR4sL8kD6wT3", string(byRule["leaklens.js.client-secret.1"].NamedGroups["client_secret"]))
	require.Equal(t, "Z8rM3pQ6", string(byRule["leaklens.js.api-secret.1"].NamedGroups["api_secret"]))
	require.Equal(t, "Demo.Config.clientSecret", compactJSReference(string(byRule["leaklens.js.basic-auth-flow.1"].NamedGroups["client_secret_ref"])))
}
