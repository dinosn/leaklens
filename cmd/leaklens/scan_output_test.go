package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/dinosn/leaklens/pkg/types"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

func TestPrintFileMatchesLabelsCryptoEvidence(t *testing.T) {
	var out bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&out)

	match := &types.Match{
		RuleID: "leaklens.js.crypto.2",
		Location: types.Location{Source: types.SourceSpan{
			Start: types.SourcePoint{Line: 12, Column: 4},
			End:   types.SourcePoint{Line: 12, Column: 30},
		}},
		Groups: [][]byte{[]byte("seal"), []byte("form.password")},
		NamedGroups: map[string][]byte{
			"aes_key":               []byte("Synthet1cKeySeed"),
			"password_input":        []byte("form.password"),
			"password_value_source": []byte("runtime input; not embedded in scanned content"),
		},
		Snippet: types.Snippet{Matching: []byte("seal(form.password)")},
	}
	rules := map[string]*types.Rule{
		match.RuleID: {ID: match.RuleID, Name: "Client-Side AES Password Encryption Flow"},
	}

	printFileMatches(cmd, newStyles(false), types.FileProvenance{FilePath: "synthetic.js"}, []*types.Match{match}, rules)
	got := out.String()
	for _, want := range []string{"aes_key:", "password_input:", "password_value_source:"} {
		require.Contains(t, got, want)
	}
	require.False(t, strings.Contains(got, "Group 1:"), got)
}
