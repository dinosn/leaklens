package rule

import (
	"testing"

	"github.com/dinosn/leaklens/pkg/matcher"
	"github.com/dinosn/leaklens/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestJavaScriptClientSecretLiteral(t *testing.T) {
	rule := loadBuiltinRuleByID(t, "leaklens.js.client-secret.1")
	require.NoError(t, ValidateRule(rule))

	m, err := matcher.NewPortableRegexp([]*types.Rule{rule}, 0)
	require.NoError(t, err)
	defer m.Close()

	testCases := []struct {
		name       string
		content    string
		wantSecret string
	}{
		{
			name:       "camel case object property",
			content:    `const config={clientId:"web_portal",clientSecret:"Q7vN2mX9pR4sL8kD6wT3"};`,
			wantSecret: "Q7vN2mX9pR4sL8kD6wT3",
		},
		{
			name:       "snake case assignment",
			content:    `const CLIENT_SECRET = 'Z8rM3pQ6vN1xK5dF7hJ2';`,
			wantSecret: "Z8rM3pQ6vN1xK5dF7hJ2",
		},
		{
			name:       "quoted hyphenated property",
			content:    `const config={"client-secret":"M4kP8vR2sN6xQ9dL3wT7"};`,
			wantSecret: "M4kP8vR2sN6xQ9dL3wT7",
		},
		{name: "runtime reference", content: `const config={clientSecret:runtime.clientSecret};`},
		{name: "environment interpolation", content: `const config={clientSecret:"${CLIENT_SECRET}"};`},
		{name: "obvious placeholder", content: `const config={clientSecret:"YOUR_CLIENT_SECRET_123456"};`},
		{name: "test placeholder", content: `const config={clientSecret:"test-secret-123456"};`},
		{name: "letters only", content: `const config={clientSecret:"abcdefghijklmnopqrst"};`},
		{name: "digits only", content: `const config={clientSecret:"12345678901234567890"};`},
		{name: "low diversity", content: `const config={clientSecret:"A1A1A1A1A1A1A1A1A1A1"};`},
		{name: "short value", content: `const config={clientSecret:"A1b2C3"};`},
		{name: "label property", content: `const clientSecretLabel="Q7vN2mX9pR4sL8kD6wT3";`},
		{name: "prefixed property", content: `const myClientSecret="Q7vN2mX9pR4sL8kD6wT3";`},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			matches, err := m.Match([]byte(tc.content))
			require.NoError(t, err)
			if tc.wantSecret == "" {
				require.Empty(t, matches)
				return
			}
			require.Len(t, matches, 1)
			require.Equal(t, tc.wantSecret, string(matches[0].NamedGroups["client_secret"]))
		})
	}
}

func TestClientSideBasicAuthenticationCredentialFlow(t *testing.T) {
	rule := loadBuiltinRuleByID(t, "leaklens.js.basic-auth-flow.1")
	require.NoError(t, ValidateRule(rule))

	m, err := matcher.NewPortableRegexp([]*types.Rule{rule}, 0)
	require.NoError(t, err)
	defer m.Close()

	testCases := []struct {
		name             string
		content          string
		wantClientID     string
		wantClientSecret string
	}{
		{
			name:             "namespaced Base64 helper",
			content:          `const headers={'Authorization':'Basic '+Demo.lib.Base64.encode(Demo.Config.clientId+':'+Demo.Config.clientSecret)};`,
			wantClientID:     "Demo.Config.clientId",
			wantClientSecret: "Demo.Config.clientSecret",
		},
		{
			name:             "btoa with snake case properties",
			content:          `headers.Authorization = "Basic " + window.btoa(config.client_id + ":" + config.client_secret);`,
			wantClientID:     "config.client_id",
			wantClientSecret: "config.client_secret",
		},
		{
			name:    "encoded pair without Basic header",
			content: `const encoded=Demo.lib.Base64.encode(Demo.Config.clientId+':'+Demo.Config.clientSecret);`,
		},
		{name: "bearer header", content: `headers.Authorization="Bearer "+token;`},
		{
			name:    "username and password Basic flow",
			content: `headers.Authorization="Basic "+window.btoa(config.username+':'+config.password);`,
		},
		{
			name:    "unrelated Base64 helper",
			content: `headers.Authorization="Basic "+codec.encode(config.clientId+':'+config.clientSecret);`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			matches, err := m.Match([]byte(tc.content))
			require.NoError(t, err)
			if tc.wantClientSecret == "" {
				require.Empty(t, matches)
				return
			}
			require.Len(t, matches, 1)
			require.Equal(t, tc.wantClientID, compactJSReference(string(matches[0].NamedGroups["client_id_ref"])))
			require.Equal(t, tc.wantClientSecret, compactJSReference(string(matches[0].NamedGroups["client_secret_ref"])))
		})
	}
}

func compactJSReference(value string) string {
	result := make([]byte, 0, len(value))
	for i := 0; i < len(value); i++ {
		switch value[i] {
		case ' ', '\t', '\r', '\n':
			continue
		default:
			result = append(result, value[i])
		}
	}
	return string(result)
}
