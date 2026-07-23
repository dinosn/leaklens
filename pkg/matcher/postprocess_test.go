package matcher

import (
	"strings"
	"testing"

	"github.com/dinosn/leaklens/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestExpandAESPasswordFlowMatchesReportsEachPasswordCall(t *testing.T) {
	content := []byte(`const c=CryptoJS,k="Synthet1cKeySeed";function seal(v){const w=c.enc.Utf8.parse(k);return c.AES.encrypt(v,w,{mode:c.mode.ECB,padding:c.pad.Pkcs7}).toString()}const changed={oldPassword:seal(form.oldPassword),newPassword:seal(form.newPassword)};const login={password:seal(login.password)};const ignored={token:seal(form.token)};`)
	start := strings.Index(string(content), "function seal")
	require.NotEqual(t, -1, start)

	rule := &types.Rule{
		ID:           aesPasswordFlowRuleID,
		Name:         "Client-Side AES Password Encryption Flow",
		StructuralID: "synthetic-structural-id",
	}
	wrapper := &types.Match{
		RuleID:       rule.ID,
		StructuralID: "wrapper",
		Location: types.Location{Offset: types.OffsetSpan{
			Start: int64(start),
			End:   int64(start + len("function seal")),
		}},
		NamedGroups: map[string][]byte{
			"aes_password_encryptor":  []byte("seal"),
			"aes_password_key_source": []byte("k"),
		},
	}

	matches := expandAESPasswordFlowMatches(content, types.ComputeBlobID(content), rule, []*types.Match{wrapper}, 0)
	require.Len(t, matches, 3)

	inputs := make(map[string]bool)
	for _, match := range matches {
		require.Equal(t, "Synthet1cKeySeed", string(match.NamedGroups["aes_key"]))
		require.Equal(t, "runtime input; not embedded in scanned content", string(match.NamedGroups["password_value_source"]))
		inputs[string(match.NamedGroups["password_input"])] = true
	}
	require.Equal(t, map[string]bool{
		"form.oldPassword": true,
		"form.newPassword": true,
		"login.password":   true,
	}, inputs)
}

func TestExpandAESPasswordFlowMatchesExposesLiteralPasswordOnlyWithPasswordContext(t *testing.T) {
	content := []byte(`const k="Synthet1cKeySeed";function seal(v){return v}const body={password:seal("Synthet1cPass!"),token:seal("Synthet1cToken!")};`)
	start := strings.Index(string(content), "function seal")
	rule := &types.Rule{ID: aesPasswordFlowRuleID, Name: "flow", StructuralID: "synthetic-structural-id"}
	wrapper := &types.Match{
		RuleID:       rule.ID,
		StructuralID: "wrapper",
		Location:     types.Location{Offset: types.OffsetSpan{Start: int64(start), End: int64(start + 1)}},
		NamedGroups: map[string][]byte{
			"aes_password_encryptor":  []byte("seal"),
			"aes_password_key_source": []byte("k"),
		},
	}

	matches := expandAESPasswordFlowMatches(content, types.ComputeBlobID(content), rule, []*types.Match{wrapper}, 0)
	require.Len(t, matches, 1)
	require.Equal(t, "Synthet1cPass!", string(matches[0].NamedGroups["password_value"]))
	require.Empty(t, matches[0].NamedGroups["password_value_source"])
}

func TestExpandAESPasswordFlowMatchesSkipsHighVolumeNonPasswordCalls(t *testing.T) {
	content := []byte(`const k="Synthet1cKeySeed";function e(v){return v}` + strings.Repeat(`e(payload);`, 5000) + `const body={password:e(form.password)};`)
	start := strings.Index(string(content), "function e")
	rule := &types.Rule{ID: aesPasswordFlowRuleID, Name: "flow", StructuralID: "synthetic-structural-id"}
	wrapper := &types.Match{
		RuleID:       rule.ID,
		StructuralID: "wrapper",
		Location:     types.Location{Offset: types.OffsetSpan{Start: int64(start), End: int64(start + 1)}},
		NamedGroups: map[string][]byte{
			"aes_password_encryptor":  []byte("e"),
			"aes_password_key_source": []byte("k"),
		},
	}

	matches := expandAESPasswordFlowMatches(content, types.ComputeBlobID(content), rule, []*types.Match{wrapper}, 0)
	require.Len(t, matches, 1)
	require.Equal(t, "form.password", string(matches[0].NamedGroups["password_input"]))
}

func TestStaticAESKeyFromWrapperDecodesEscapedLiteral(t *testing.T) {
	wrapper := &types.Match{NamedGroups: map[string][]byte{
		"aes_password_static_key_double": []byte(`Synthet1c\x4beySeed`),
	}}
	require.Equal(t, "Synthet1cKeySeed", staticAESKeyFromWrapper(wrapper))
}
