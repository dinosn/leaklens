package enum

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dinosn/leaklens/pkg/types"
)

func TestURLEnumerator_AllFailedReturnsError(t *testing.T) {
	enumerator := NewURLEnumerator([]string{"not-a-url"}, 1024)

	err := enumerator.Enumerate(context.Background(), func(content []byte, blobID types.BlobID, prov types.Provenance) error {
		t.Fatal("callback should not be called for failed URL")
		return nil
	})

	if err == nil {
		t.Fatal("expected all-failed URL scan to return an error")
	}
	if !strings.Contains(err.Error(), "all URL fetches failed") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestURLEnumeratorDefaultMaxSizeIs20MB(t *testing.T) {
	enumerator := NewURLEnumerator([]string{"https://example.invalid/app.js"}, 0)
	if enumerator.MaxSize != 20*1024*1024 {
		t.Fatalf("default URL max size = %d, want %d", enumerator.MaxSize, 20*1024*1024)
	}
}

func TestURLEnumerator_MixedFailureAndSuccessReturnsContent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("const token = 'testsecret_ABC123';"))
	}))
	defer server.Close()

	enumerator := NewURLEnumerator([]string{"not-a-url", server.URL + "/app.js"}, 1024)
	var count int
	err := enumerator.Enumerate(context.Background(), func(content []byte, blobID types.BlobID, prov types.Provenance) error {
		count++
		if string(content) != "const token = 'testsecret_ABC123';" {
			t.Fatalf("unexpected content: %q", string(content))
		}
		if prov.Kind() != "url" {
			t.Fatalf("expected URL provenance, got %s", prov.Kind())
		}
		return nil
	})

	if err != nil {
		t.Fatalf("expected mixed URL scan to succeed, got %v", err)
	}
	if count != 1 {
		t.Fatalf("expected 1 successful URL callback, got %d", count)
	}
}

func TestURLEnumerator_RetriesCertificateVerificationFailure(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("const token = 'testsecret_TLS123';"))
	}))
	defer server.Close()

	var logs bytes.Buffer
	restore := SetLogOutput(&logs)
	defer restore()

	enumerator := NewURLEnumerator([]string{server.URL + "/app.js"}, 1024)
	var count int
	err := enumerator.Enumerate(context.Background(), func(content []byte, blobID types.BlobID, prov types.Provenance) error {
		count++
		if string(content) != "const token = 'testsecret_TLS123';" {
			t.Fatalf("unexpected content: %q", string(content))
		}
		return nil
	})

	if err != nil {
		t.Fatalf("expected TLS fallback URL scan to succeed, got %v", err)
	}
	if count != 1 {
		t.Fatalf("expected 1 successful URL callback, got %d", count)
	}
	if !strings.Contains(logs.String(), "TLS certificate verification failed") {
		t.Fatalf("expected TLS verification warning, got logs: %s", logs.String())
	}
}
