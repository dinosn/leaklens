package main

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/dinosn/leaklens/pkg/matcher"
)

const maxAESCiphertextEvidence = 1024

func loadScanAESCiphertexts() ([]matcher.AESCiphertextEvidence, error) {
	var evidence []matcher.AESCiphertextEvidence
	seen := make(map[string]struct{})
	appendEvidence := func(encoded, source string) error {
		ciphertext, err := decodeAESCiphertext(encoded)
		if err != nil {
			return fmt.Errorf("invalid AES ciphertext from %s: %w", source, err)
		}
		key := string(ciphertext)
		if _, ok := seen[key]; ok {
			return nil
		}
		if len(evidence) >= maxAESCiphertextEvidence {
			return fmt.Errorf("too many AES ciphertexts: maximum is %d", maxAESCiphertextEvidence)
		}
		seen[key] = struct{}{}
		evidence = append(evidence, matcher.AESCiphertextEvidence{
			Ciphertext: ciphertext,
			Source:     source,
		})
		return nil
	}

	for i, encoded := range scanAESCiphertexts {
		if err := appendEvidence(encoded, fmt.Sprintf("--aes-ciphertext[%d]", i+1)); err != nil {
			return nil, err
		}
	}
	if scanAESCiphertextFile == "" {
		return evidence, nil
	}

	var reader io.Reader
	sourceName := "stdin"
	if scanAESCiphertextFile == "-" {
		reader = os.Stdin
	} else {
		file, err := os.Open(scanAESCiphertextFile)
		if err != nil {
			return nil, fmt.Errorf("opening AES ciphertext file: %w", err)
		}
		defer file.Close()
		reader = file
		sourceName = filepath.Base(scanAESCiphertextFile)
	}

	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 4096), 1024*1024)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if err := appendEvidence(line, fmt.Sprintf("%s:%d", sourceName, lineNumber)); err != nil {
			return nil, err
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading AES ciphertext file: %w", err)
	}
	if len(evidence) == 0 {
		return nil, fmt.Errorf("no AES ciphertexts found in %s", scanAESCiphertextFile)
	}
	return evidence, nil
}

func decodeAESCiphertext(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, fmt.Errorf("value is empty")
	}
	encodings := []*base64.Encoding{
		base64.StdEncoding.Strict(),
		base64.RawStdEncoding.Strict(),
		base64.URLEncoding.Strict(),
		base64.RawURLEncoding.Strict(),
	}
	var ciphertext []byte
	for _, encoding := range encodings {
		decoded, err := encoding.DecodeString(value)
		if err == nil {
			ciphertext = decoded
			break
		}
	}
	if len(ciphertext) == 0 {
		return nil, fmt.Errorf("expected non-empty base64")
	}
	if len(ciphertext)%16 != 0 {
		return nil, fmt.Errorf("decoded length %d is not an AES block multiple", len(ciphertext))
	}
	return ciphertext, nil
}
