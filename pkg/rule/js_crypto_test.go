package rule

import (
	"testing"

	"github.com/dinosn/leaklens/pkg/matcher"
	"github.com/dinosn/leaklens/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestClientSideAESKeyCandidate(t *testing.T) {
	rule := loadBuiltinRuleByID(t, "leaklens.js.crypto.1")
	m, err := matcher.NewPortableRegexp([]*types.Rule{rule}, 0)
	require.NoError(t, err)

	tests := []struct {
		name    string
		content string
		want    bool
	}{
		{
			name:    "observed g_ac convention",
			content: `var g_ac = "A1!bcdefghijklmn";`,
			want:    true,
		},
		{
			name:    "observed g_ac alphanumeric convention",
			content: `var g_ac = "A1bcdefghijklmno";`,
			want:    true,
		},
		{
			name:    "semantic aes key",
			content: `const aesKey = "a1bcdefghijklmno";`,
			want:    true,
		},
		{
			name:    "semantic secret key",
			content: `const secretKey = "a1bcdefghijklmno";`,
			want:    true,
		},
		{
			name:    "minified AES length guard",
			content: `function encrypt(e){const n="a1bcdefghijklmno";if(!n||16!==n.length)return console.error("AES key must be 16 bytes"),"";const r=CryptoJS.enc.Utf8.parse(n);return CryptoJS.AES.encrypt(e,r).toString()}`,
			want:    true,
		},
		{
			name:    "semantic crypto object property",
			content: `{"cryptoSecret": "a1bcdefghijklmno"}`,
			want:    true,
		},
		{
			name:    "hex encoded AES-GCM key property",
			content: `const cfg = {EncKG: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}; crypto.subtle.importKey("raw", key, {name: "AES-GCM"}, false, ["encrypt", "decrypt"]);`,
			want:    true,
		},
		{
			name:    "hex encoded AES key property",
			content: `const cfg = {EncK: "0123456789abcdef0123456789abcdef"}; const key = CryptoJS.enc.Hex.parse(cfg.EncK);`,
			want:    true,
		},
		{
			name:    "React passphrase flowing into AES",
			content: `const env={REACT_APP_FORM_PASSPHRASE:"S7nthetic/passphrase"};const key=env.REACT_APP_FORM_PASSPHRASE;CryptoJS.AES.encrypt(payload,key);`,
			want:    true,
		},
		{
			name:    "literal AES encryption passphrase",
			content: `CryptoJS.AES.encrypt(payload,"S7nthetic/passphrase")`,
			want:    true,
		},
		{
			name:    "minified literal AES decryption passphrase",
			content: `crypto.AES.decrypt(ciphertext,"S7nthetic/passphrase")`,
			want:    true,
		},
		{
			name:    "short literal AES ECB PKCS7 passphrase",
			content: `CryptoJS.AES.encrypt(password,"SyntK3y!",{mode:CryptoJS.mode.ECB,padding:CryptoJS.pad.Pkcs7})`,
			want:    true,
		},
		{
			name:    "short CryptoJS alias parsed passphrase constant flows into AES key",
			content: `const a="SyntK3y!";function e(p){const k=c.enc.Utf8.parse(a);return c.AES.encrypt(p,k,{mode:c.mode.ECB,padding:c.pad.Pkcs7}).toString()}`,
			want:    true,
		},
		{
			name:    "CryptoJS alias parsed passphrase constant flows into AES key",
			content: `const a="S7nthetic/pass123";function e(p){const k=c.enc.Utf8.parse(a);return c.AES.encrypt(p,k,{mode:c.mode.ECB,padding:c.pad.Pkcs7}).toString()}`,
			want:    true,
		},
		{
			name:    "CryptoJS comma-declared parsed passphrase constant flows into AES key",
			content: `const c=loadCrypto(),a="S7nthetic/pass123";function e(p){const k=c.enc.Utf8.parse(a);return c.AES.encrypt(p,k,{mode:c.mode.ECB,padding:c.pad.Pkcs7}).toString()}`,
			want:    true,
		},
		{
			name:    "CryptoJS default parameter passphrase flows into AES key",
			content: `function e(p,a="S7nthetic/pass123"){const k=c.enc.Utf8.parse(a);return c.AES.decrypt(p,k,{mode:c.mode.ECB,padding:c.pad.Pkcs7}).toString(c.enc.Utf8)}`,
			want:    true,
		},
		{
			name:    "PBKDF2 passphrase flows into AES key",
			content: `const passPhrase="Synthet!c Pass";const key=CryptoJS.PBKDF2(passPhrase,CryptoJS.enc.Hex.parse(salt),{keySize:4,iterations:10000});const encrypted=CryptoJS.AES.encrypt(password,key,{iv:iv});`,
			want:    true,
		},
		{
			name:    "g_ac low complexity",
			content: `var g_ac = "abcdefghijklmnop";`,
			want:    false,
		},
		{
			name:    "no crypto variable context",
			content: `var displayName = "A1!bcdefghijklmn";`,
			want:    false,
		},
		{
			name:    "generic access key does not imply AES",
			content: `const accessKey = "a1bcdefghijklmno";`,
			want:    false,
		},
		{
			name:    "minified non-crypto length guard",
			content: `function normalize(e){const n="a1bcdefghijklmno";if(!n||16!==n.length)return "";return n.toLowerCase()}`,
			want:    false,
		},
		{
			name:    "wrong key length",
			content: `const aesKey = "short";`,
			want:    false,
		},
		{
			name:    "hex encoded iv is not a key",
			content: `const cfg = {Iv: "0123456789abcdef0123456789abcdef"};`,
			want:    false,
		},
		{
			name:    "public React API key without AES use",
			content: `const env={REACT_APP_PUBLIC_WIDGET_KEY:"PublicClient42Value"};render(env.REACT_APP_PUBLIC_WIDGET_KEY);`,
			want:    false,
		},
		{
			name:    "survey key without AES use",
			content: `const env={REACT_APP_FORM_PASSPHRASE:"S7nthetic/passphrase"};send(env.REACT_APP_FORM_PASSPHRASE);`,
			want:    false,
		},
		{
			name:    "short AES argument",
			content: `CryptoJS.AES.encrypt(payload,"short1!")`,
			want:    false,
		},
		{
			name:    "short AES CBC argument",
			content: `CryptoJS.AES.encrypt(payload,"short1!",{mode:CryptoJS.mode.CBC,padding:CryptoJS.pad.Pkcs7})`,
			want:    false,
		},
		{
			name:    "passphrase label is not AES argument",
			content: `CryptoJS.AES.encrypt(payload,runtimeKey,{label:"S7nthetic/passphrase"})`,
			want:    false,
		},
		{
			name:    "parsed constant used only as iv is not AES key",
			content: `const a="S7nthetic/pass123";function e(p){const iv=c.enc.Utf8.parse(a);return c.AES.encrypt(p,runtimeKey,{iv:iv,mode:c.mode.CBC,padding:c.pad.Pkcs7}).toString()}`,
			want:    false,
		},
		{
			name:    "parsed default parameter used only as iv is not AES key",
			content: `function e(p,a="S7nthetic/pass123"){const iv=c.enc.Utf8.parse(a);return c.AES.decrypt(p,runtimeKey,{iv:iv,mode:c.mode.CBC,padding:c.pad.Pkcs7}).toString(c.enc.Utf8)}`,
			want:    false,
		},
		{
			name:    "Spanish endpoint name containing aes substring is not AES key",
			content: `const consultaEstablecimientosDesplegableServicio_v1_URI = "/v1/establecimientos/desplegable";`,
			want:    false,
		},
		{
			name:    "PBKDF2 passphrase without AES use is not key",
			content: `const passPhrase="Synthet!c Pass";send(passPhrase);`,
			want:    false,
		},
		{
			name:    "PBKDF2 runtime passphrase with static iv is not key",
			content: `const iv="0123456789abcdef0123456789abcdef";const key=CryptoJS.PBKDF2(runtimePass,CryptoJS.enc.Hex.parse(iv),{keySize:4});CryptoJS.AES.encrypt(password,key,{iv:ivWord});`,
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches, err := m.Match([]byte(tt.content))
			require.NoError(t, err)
			if tt.want {
				require.Len(t, matches, 1)
				require.Equal(t, "leaklens.js.crypto.1", matches[0].RuleID)
				return
			}
			require.Empty(t, matches)
		})
	}
}

func TestClientSideAESPasswordEncryptionFlow(t *testing.T) {
	rule := loadBuiltinRuleByID(t, "leaklens.js.crypto.2")
	m, err := matcher.NewPortableRegexp([]*types.Rule{rule}, 0)
	require.NoError(t, err)

	tests := []struct {
		name       string
		content    string
		want       bool
		wantInput  string
		wantFnName string
	}{
		{
			name:       "minified function encrypts old password with AES ECB PKCS7",
			content:    `const c=CryptoJS,k="Synthet1cKeySeed";function bR(n){const e=c.enc.Utf8.parse(k);return c.AES.encrypt(n,e,{mode:c.mode.ECB,padding:c.pad.Pkcs7}).toString()}const body={oldPassword:bR(form.oldPassword),newPassword:bR(form.newPassword)};`,
			want:       true,
			wantInput:  "form.oldPassword",
			wantFnName: "bR",
		},
		{
			name:       "assignment encrypts password property with AES ECB PKCS7",
			content:    `const c=CryptoJS;function seal(v){const e=c.enc.Utf8.parse(secret);return c.AES.encrypt(v,e,{mode:c.mode.ECB,padding:c.pad.Pkcs7}).toString()}request.password=seal(request.password);`,
			want:       true,
			wantInput:  "request.password",
			wantFnName: "seal",
		},
		{
			name:       "arrow encryptor handles pwd property",
			content:    `const enc=p=>{const k=c.enc.Utf8.parse(secret);return c.AES.encrypt(p,k,{mode:c.mode.ECB,padding:c.pad.Pkcs7}).toString()};payload.pwd=enc(payload.pwd);`,
			want:       true,
			wantInput:  "payload.pwd",
			wantFnName: "enc",
		},
		{
			name:    "password name without crypto wrapper",
			content: `function bR(n){return encodeURIComponent(n)}const body={oldPassword:bR(form.oldPassword)};`,
			want:    false,
		},
		{
			name:    "CBC mode password encryption is left to other crypto rules",
			content: `function bR(n){const e=CryptoJS.enc.Utf8.parse(k);return CryptoJS.AES.encrypt(n,e,{mode:CryptoJS.mode.CBC,padding:CryptoJS.pad.Pkcs7}).toString()}const body={oldPassword:bR(form.oldPassword)};`,
			want:    false,
		},
		{
			name:    "ECB wrapper used for non-password token is not password flow",
			content: `function bR(n){const e=CryptoJS.enc.Utf8.parse(k);return CryptoJS.AES.encrypt(n,e,{mode:CryptoJS.mode.ECB,padding:CryptoJS.pad.Pkcs7}).toString()}const body={token:bR(form.token)};`,
			want:    false,
		},
		{
			name:    "AES decrypt helper is not password encryption flow",
			content: `function dec(n){const e=CryptoJS.enc.Utf8.parse(k);return CryptoJS.AES.decrypt(n,e,{mode:CryptoJS.mode.ECB,padding:CryptoJS.pad.Pkcs7}).toString(CryptoJS.enc.Utf8)}const body={password:dec(form.password)};`,
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches, err := m.Match([]byte(tt.content))
			require.NoError(t, err)
			if tt.want {
				require.Len(t, matches, 1)
				require.Equal(t, "leaklens.js.crypto.2", matches[0].RuleID)

				named := matches[0].NamedGroups
				gotInput := string(named["aes_password_input"])
				gotFn := string(named["aes_password_encryptor"])
				if gotInput == "" {
					gotInput = string(named["aes_password_input_arrow"])
				}
				if gotFn == "" {
					gotFn = string(named["aes_password_encryptor_arrow"])
				}
				require.Equal(t, tt.wantInput, gotInput)
				require.Equal(t, tt.wantFnName, gotFn)
				return
			}
			require.Empty(t, matches)
		})
	}
}

func TestClientSideAESPasswordEncryptionFlowReportsEveryCallSite(t *testing.T) {
	rule := loadBuiltinRuleByID(t, "leaklens.js.crypto.2")
	m, err := matcher.New(matcher.Config{Rules: []*types.Rule{rule}})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, m.Close()) })

	content := []byte(`const c=CryptoJS,k="Synthet1cKeySeed";function seal(v){const w=c.enc.Utf8.parse(k);return c.AES.encrypt(v,w,{mode:c.mode.ECB,padding:c.pad.Pkcs7}).toString()}const change={oldPassword:seal(form.oldPassword),newPassword:seal(form.newPassword)};const login={password:seal(login.password)};`)
	matches, err := m.Match(content)
	require.NoError(t, err)
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

func TestClientSideAESPasswordEncryptionFlowCapturesRuntimeValues(t *testing.T) {
	rule := loadBuiltinRuleByID(t, "leaklens.js.crypto.2")
	m, err := matcher.NewPortableRegexp([]*types.Rule{rule}, 0)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, m.Close()) })

	content := []byte(`const leaklens_runtime_crypto_mode = "ECB"; const leaklens_runtime_crypto_padding = "Pkcs7"; const leaklens_runtime_crypto_password = "Synthet1cPass!"; const leaklens_runtime_crypto_key = "Synthet1cKeySeed"; const leaklens_runtime_crypto_ciphertext = "U3ludGhldGljQ2lwaGVy";`)
	matches, err := m.Match(content)
	require.NoError(t, err)
	require.Len(t, matches, 1)
	require.Equal(t, "Synthet1cPass!", string(matches[0].NamedGroups["runtime_aes_password"]))
	require.Equal(t, "Synthet1cKeySeed", string(matches[0].NamedGroups["runtime_aes_key"]))
	require.Equal(t, "U3ludGhldGljQ2lwaGVy", string(matches[0].NamedGroups["runtime_aes_ciphertext"]))

	withoutCiphertext := []byte(`const leaklens_runtime_crypto_mode = "ECB"; const leaklens_runtime_crypto_padding = "Pkcs7"; const leaklens_runtime_crypto_password = "Synthet1cPass!"; const leaklens_runtime_crypto_key = "Synthet1cKeySeed";`)
	matches, err = m.Match(withoutCiphertext)
	require.NoError(t, err)
	require.Len(t, matches, 1)
	require.Equal(t, "Synthet1cPass!", string(matches[0].NamedGroups["runtime_aes_password"]))
	require.Equal(t, "Synthet1cKeySeed", string(matches[0].NamedGroups["runtime_aes_key"]))
}

func TestClientSideAESPasswordEncryptionFlowRejectsUnprovenRuntimeContext(t *testing.T) {
	rule := loadBuiltinRuleByID(t, "leaklens.js.crypto.2")
	m, err := matcher.NewPortableRegexp([]*types.Rule{rule}, 0)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, m.Close()) })

	for _, content := range [][]byte{
		[]byte(`const leaklens_runtime_crypto_mode = "CBC"; const leaklens_runtime_crypto_padding = "Pkcs7"; const leaklens_runtime_crypto_password = "Synthet1cPass!"; const leaklens_runtime_crypto_key = "Synthet1cKeySeed";`),
		[]byte(`const leaklens_runtime_crypto_mode = "ECB"; const leaklens_runtime_crypto_padding = "Pkcs7"; const leaklens_runtime_crypto_data = "Synthet1cPayload"; const leaklens_runtime_crypto_key = "Synthet1cKeySeed";`),
	} {
		matches, err := m.Match(content)
		require.NoError(t, err)
		require.Empty(t, matches)
	}
}

func loadBuiltinRuleByID(t *testing.T, id string) *types.Rule {
	t.Helper()
	loader := NewLoader()
	rules, err := loader.LoadBuiltinRules()
	require.NoError(t, err)
	for _, rule := range rules {
		if rule.ID == id {
			return rule
		}
	}
	t.Fatalf("rule %s not found", id)
	return nil
}
