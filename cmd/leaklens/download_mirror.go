package main

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	pathpkg "path"
	"path/filepath"
	"strings"
	"sync"
	"unicode"

	"github.com/dinosn/leaklens/pkg/types"
)

type downloadMirror struct {
	root string
	mu   sync.Mutex
}

func newDownloadMirror(root string) (*downloadMirror, error) {
	if root == "" {
		return nil, fmt.Errorf("--download-dir must not be empty")
	}
	if info, err := os.Stat(root); err == nil && !info.IsDir() {
		return nil, fmt.Errorf("--download-dir exists and is not a directory: %s", root)
	} else if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("checking --download-dir: %w", err)
	}
	if err := os.MkdirAll(root, 0755); err != nil {
		return nil, fmt.Errorf("creating --download-dir: %w", err)
	}
	return &downloadMirror{root: root}, nil
}

func (m *downloadMirror) Save(content []byte, blobID types.BlobID, prov types.Provenance) (bool, error) {
	urlProv, ok := prov.(types.URLProvenance)
	if !ok {
		return false, nil
	}

	relPath, err := mirroredURLPath(urlProv.URL)
	if err != nil {
		return false, err
	}
	dest := filepath.Join(m.root, relPath)

	m.mu.Lock()
	defer m.mu.Unlock()

	if err := os.MkdirAll(filepath.Dir(dest), 0755); err != nil {
		return false, fmt.Errorf("creating mirror directory: %w", err)
	}

	dest, shouldWrite, err := mirrorDestination(dest, content, blobID)
	if err != nil || !shouldWrite {
		return shouldWrite, err
	}

	tmp := dest + ".tmp"
	if err := os.WriteFile(tmp, content, 0644); err != nil {
		return false, fmt.Errorf("writing mirror file: %w", err)
	}
	if err := os.Rename(tmp, dest); err != nil {
		_ = os.Remove(tmp)
		return false, fmt.Errorf("renaming mirror file: %w", err)
	}
	return true, nil
}

func mirrorDestination(dest string, content []byte, blobID types.BlobID) (string, bool, error) {
	existing, err := os.ReadFile(dest)
	if err == nil {
		if bytes.Equal(existing, content) {
			return dest, false, nil
		}
		ext := filepath.Ext(dest)
		base := strings.TrimSuffix(dest, ext)
		dest = fmt.Sprintf("%s__%s%s", base, blobID.Hex()[:12], ext)
		existing, err = os.ReadFile(dest)
		if err == nil {
			return dest, !bytes.Equal(existing, content), nil
		}
	}
	if err != nil && !os.IsNotExist(err) {
		return "", false, fmt.Errorf("checking mirror file: %w", err)
	}
	return dest, true, nil
}

func mirroredURLPath(rawURL string) (string, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("invalid URL %q: %w", rawURL, err)
	}
	if parsed.Host == "" {
		return "", fmt.Errorf("invalid URL %q: missing host", rawURL)
	}

	segments := []string{sanitizeMirrorSegment(parsed.Host)}
	for _, segment := range strings.Split(parsed.EscapedPath(), "/") {
		if segment == "" {
			continue
		}
		decoded, err := url.PathUnescape(segment)
		if err != nil {
			decoded = segment
		}
		segments = append(segments, sanitizeMirrorSegment(decoded))
	}

	if len(segments) == 1 || strings.HasSuffix(parsed.Path, "/") {
		segments = append(segments, "index")
	}

	if parsed.RawQuery != "" {
		last := segments[len(segments)-1]
		ext := pathpkg.Ext(last)
		base := strings.TrimSuffix(last, ext)
		if base == "" {
			base = "index"
		}
		segments[len(segments)-1] = base + "__query_" + sanitizeMirrorQuery(parsed.RawQuery) + ext
	}

	return filepath.Join(segments...), nil
}

func sanitizeMirrorQuery(value string) string {
	token := sanitizeMirrorSegment(value)
	if len(token) <= 80 {
		return token
	}
	sum := sha1.Sum([]byte(value))
	return token[:80] + "_" + hex.EncodeToString(sum[:])[:8]
}

func sanitizeMirrorSegment(value string) string {
	value = strings.TrimSpace(value)
	var b strings.Builder
	lastUnderscore := false
	for _, r := range value {
		if isMirrorSafeRune(r) {
			b.WriteRune(r)
			lastUnderscore = false
			continue
		}
		if !lastUnderscore {
			b.WriteByte('_')
			lastUnderscore = true
		}
	}
	out := strings.Trim(b.String(), "._- ")
	if out == "" || out == "." || out == ".." {
		return "_"
	}
	return out
}

func isMirrorSafeRune(r rune) bool {
	return unicode.IsLetter(r) ||
		unicode.IsDigit(r) ||
		r == '.' ||
		r == '-' ||
		r == '_' ||
		r == '='
}
