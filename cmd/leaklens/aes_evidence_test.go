package main

import (
	"bytes"
	"crypto/aes"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

func TestLoadScanAESCiphertextsCombinesAndDeduplicatesInputs(t *testing.T) {
	oldValues := append([]string(nil), scanAESCiphertexts...)
	oldFile := scanAESCiphertextFile
	t.Cleanup(func() {
		scanAESCiphertexts = oldValues
		scanAESCiphertextFile = oldFile
	})

	first := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))
	second := base64.StdEncoding.EncodeToString([]byte("fedcba9876543210"))
	path := filepath.Join(t.TempDir(), "synthetic-ciphertexts.txt")
	require.NoError(t, os.WriteFile(path, []byte("# synthetic evidence\n"+first+"\n"+second+"\n"), 0600))
	scanAESCiphertexts = []string{first}
	scanAESCiphertextFile = path

	evidence, err := loadScanAESCiphertexts()
	require.NoError(t, err)
	require.Len(t, evidence, 2)
	require.Equal(t, []byte("0123456789abcdef"), evidence[0].Ciphertext)
	require.Equal(t, []byte("fedcba9876543210"), evidence[1].Ciphertext)
	require.Equal(t, "--aes-ciphertext[1]", evidence[0].Source)
	require.Equal(t, "synthetic-ciphertexts.txt:3", evidence[1].Source)
}

func TestLoadScanAESCiphertextsRejectsInvalidBlockLength(t *testing.T) {
	oldValues := append([]string(nil), scanAESCiphertexts...)
	oldFile := scanAESCiphertextFile
	t.Cleanup(func() {
		scanAESCiphertexts = oldValues
		scanAESCiphertextFile = oldFile
	})

	scanAESCiphertexts = []string{base64.StdEncoding.EncodeToString([]byte("short-block"))}
	scanAESCiphertextFile = ""
	_, err := loadScanAESCiphertexts()
	require.ErrorContains(t, err, "not an AES block multiple")
}

func TestValidateScanOptionsRejectsTwoStdinReaders(t *testing.T) {
	oldURLFile := scanURLFile
	oldEvidenceFile := scanAESCiphertextFile
	t.Cleanup(func() {
		scanURLFile = oldURLFile
		scanAESCiphertextFile = oldEvidenceFile
	})

	scanURLFile = "-"
	scanAESCiphertextFile = "-"
	require.ErrorContains(t, validateScanOptions(), "cannot both read from stdin")
}

func TestRunEnumeratorScanPrintsDecryptedAESPasswordEvidence(t *testing.T) {
	const key = "Synthet1cKeySeed"
	const password = "Synthet1cPass!"
	setScanGlobalsForRegression(t, "", ":memory:")
	scanAESCiphertexts = []string{base64.StdEncoding.EncodeToString(encryptAESECBForCommandTest(t, key, []byte(password)))}

	var out bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&out)
	content := []byte(`const c=CryptoJS,k="Synthet1cKeySeed";function seal(v){const w=c.enc.Utf8.parse(k);return c.AES.encrypt(v,w,{mode:c.mode.ECB,padding:c.pad.Pkcs7}).toString()}const body={password:seal(form.password)};`)
	err := runEnumeratorScan(cmd, oneBlobEnumerator{content: content, path: "synthetic.js"})
	require.NoError(t, err)
	require.Contains(t, out.String(), "password_value:")
	require.Contains(t, out.String(), password)
	require.Contains(t, out.String(), "exact runtime call site not observed")
}

func encryptAESECBForCommandTest(t *testing.T, key string, plaintext []byte) []byte {
	t.Helper()
	block, err := aes.NewCipher([]byte(key))
	require.NoError(t, err)
	padding := block.BlockSize() - len(plaintext)%block.BlockSize()
	padded := append(append([]byte(nil), plaintext...), bytes.Repeat([]byte{byte(padding)}, padding)...)
	ciphertext := make([]byte, len(padded))
	for offset := 0; offset < len(padded); offset += block.BlockSize() {
		block.Encrypt(ciphertext[offset:offset+block.BlockSize()], padded[offset:offset+block.BlockSize()])
	}
	return ciphertext
}
