//go:build !wasm && cgo && vectorscan

package rule

import (
	"testing"

	"github.com/dinosn/leaklens/pkg/matcher"
	"github.com/dinosn/leaklens/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestClientSideAESVariablePassphraseVectorscan(t *testing.T) {
	rule := loadBuiltinRuleByID(t, "leaklens.js.crypto.1")
	m, err := matcher.NewVectorscan([]*types.Rule{rule}, 0)
	require.NoError(t, err)
	defer m.Close()

	matches, err := m.Match([]byte(`const c=loadCrypto(),q="S7nthetic/passphrase";function e(v){return c.AES.encrypt(v,q).toString()}`))
	require.NoError(t, err)
	require.Len(t, matches, 1)
	require.Equal(t, "S7nthetic/passphrase", string(matches[0].NamedGroups["token"]))

	matches, err = m.Match([]byte(`const q="S7nthetic/passphrase";CryptoJS.AES.encrypt(payload,runtimeKey,{iv:q})`))
	require.NoError(t, err)
	require.Empty(t, matches)
}
