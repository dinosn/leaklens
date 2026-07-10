package rule

import (
	"testing"

	"github.com/dinosn/leaklens/pkg/matcher"
	"github.com/dinosn/leaklens/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestReactAppCompiledConfiguration(t *testing.T) {
	testCases := []struct {
		name      string
		ruleID    string
		content   string
		wantValue string
	}{
		{
			name:      "compiled username property",
			ruleID:    "np.reactapp.1",
			content:   `const env={REACT_APP_DEMO_USERNAME:"guest_user@example.test"};`,
			wantValue: "guest_user@example.test",
		},
		{
			name:      "quoted compiled username property",
			ruleID:    "np.reactapp.1",
			content:   `const env={"REACT_APP_DEMO_USERNAME":'guest_user@example.test'};`,
			wantValue: "guest_user@example.test",
		},
		{
			name:      "compiled password property",
			ruleID:    "np.reactapp.2",
			content:   `const env={REACT_APP_DEMO_PASSWORD:"S7nthetic/value-42"};`,
			wantValue: "S7nthetic/value-42",
		},
		{
			name:      "quoted compiled password property",
			ruleID:    "np.reactapp.2",
			content:   `const env={"REACT_APP_DEMO_PASSWORD":'S7nthetic/value-42'};`,
			wantValue: "S7nthetic/value-42",
		},
		{
			name:      "env assignment remains supported",
			ruleID:    "np.reactapp.2",
			content:   `REACT_APP_AUTH_PASSWORD=S7nthetic/value-42`,
			wantValue: "S7nthetic/value-42",
		},
		{
			name:    "runtime username expression",
			ruleID:  "np.reactapp.1",
			content: `const env={REACT_APP_DEMO_USERNAME:runtime.username};`,
		},
		{
			name:    "runtime password expression",
			ruleID:  "np.reactapp.2",
			content: `const env={REACT_APP_DEMO_PASSWORD:runtime.password};`,
		},
		{
			name:    "environment variable interpolation",
			ruleID:  "np.reactapp.2",
			content: `REACT_APP_AUTH_PASSWORD=$RUNTIME_PASSWORD`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rule := loadBuiltinRuleByID(t, tc.ruleID)
			m, err := matcher.NewPortableRegexp([]*types.Rule{rule}, 0)
			require.NoError(t, err)
			defer m.Close()

			matches, err := m.Match([]byte(tc.content))
			require.NoError(t, err)
			if tc.wantValue == "" {
				require.Empty(t, matches)
				return
			}
			require.Len(t, matches, 1)
			require.Len(t, matches[0].Groups, 1)
			require.Equal(t, tc.wantValue, string(matches[0].Groups[0]))
		})
	}
}
