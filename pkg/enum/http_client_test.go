package enum

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestTLSFallbackHTTPClientWarnsOncePerAuthorityAcrossClients(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	defer server.Close()

	var logs bytes.Buffer
	restore := SetLogOutput(&logs)
	defer restore()

	for i := 0; i < 2; i++ {
		client := newTLSFallbackHTTPClient(5 * time.Second)
		resp, err := client.Get(server.URL)
		if err != nil {
			t.Fatalf("request %d failed: %v", i+1, err)
		}
		resp.Body.Close()
	}

	warning := "TLS certificate verification failed for " + server.URL
	if got := strings.Count(logs.String(), warning); got != 1 {
		t.Fatalf("expected one TLS warning for %s, got %d logs: %s", server.URL, got, logs.String())
	}
}
