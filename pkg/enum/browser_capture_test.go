package enum

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/dinosn/leaklens/pkg/types"
)

func TestBrowserCaptureFallbackContinuesStandardCrawl(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			fmt.Fprint(w, `<script src="/assets/app.js"></script>`)
		case "/assets/app.js":
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprint(w, `const ok = "synthetic";`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	oldRunner := runBrowserRuntimeCapture
	runBrowserRuntimeCapture = func(context.Context, *CrawlEnumerator) (browserCaptureResult, error) {
		return browserCaptureResult{}, errors.New("synthetic browser launch failure")
	}
	t.Cleanup(func() {
		runBrowserRuntimeCapture = oldRunner
	})

	var logs bytes.Buffer
	restoreLog := SetLogOutput(&logs)
	defer restoreLog()

	var paths []string
	enumerator := NewCrawlEnumerator(CrawlConfig{
		TargetURL:      server.URL,
		Timeout:        2 * time.Second,
		BrowserCapture: true,
	})
	err := enumerator.Enumerate(context.Background(), func(content []byte, blobID types.BlobID, prov types.Provenance) error {
		paths = append(paths, prov.Path())
		return nil
	})
	if err != nil {
		t.Fatalf("crawl should continue after browser fallback: %v", err)
	}
	if len(paths) != 1 || !strings.HasSuffix(paths[0], "/assets/app.js") {
		t.Fatalf("fallback crawl did not scan expected asset: %#v", paths)
	}
	if got := logs.String(); !strings.Contains(got, "browser runtime capture unavailable; continuing with standard crawl only") {
		t.Fatalf("missing browser fallback warning in logs:\n%s", got)
	}
}

func TestBrowserRuntimeCryptoBlobsIncludeShortECBKey(t *testing.T) {
	events := []browserRuntimeEvent{
		{
			Seq:     1,
			Kind:    "cryptojs_aes",
			Method:  "CryptoJS.AES.encrypt",
			Mode:    "ECB",
			Padding: "Pkcs7",
			Data:    browserRuntimeValue{Type: "string", Value: "P4ssw0rd!"},
			Key:     browserRuntimeValue{Type: "string", Value: "SyntK3y!"},
			Result:  browserRuntimeValue{Type: "string", Value: "U3ludGhldGljQ2lwaGVy"},
		},
	}

	blobs := browserRuntimeCryptoBlobs("https://app.example.test/", events)
	if len(blobs) != 1 {
		t.Fatalf("expected one crypto blob, got %d", len(blobs))
	}
	content := string(blobs[0].Content)
	for _, want := range []string{
		`leaklens_runtime_crypto_password = "P4ssw0rd!"`,
		`CryptoJS.AES.encrypt(leaklens_runtime_crypto_password, "SyntK3y!", {mode: CryptoJS.mode.ECB, padding: CryptoJS.pad.Pkcs7});`,
		`leaklens_runtime_crypto_ciphertext = "U3ludGhldGljQ2lwaGVy"`,
	} {
		if !strings.Contains(content, want) {
			t.Fatalf("runtime crypto blob missing %q:\n%s", want, content)
		}
	}
	if got := blobs[0].Provenance.Path(); !strings.HasPrefix(got, "browser-runtime://app.example.test/crypto/") {
		t.Fatalf("unexpected runtime provenance path: %s", got)
	}
}

func TestNearestRuntimeUtf8CandidateRequiresAESKeyShape(t *testing.T) {
	events := []browserRuntimeEvent{
		{Value: browserRuntimeValue{Value: "plain"}},
		{Value: browserRuntimeValue{Value: "SyntK3y!"}},
	}
	if got := nearestRuntimeUtf8Candidate(events); got != "SyntK3y!" {
		t.Fatalf("unexpected nearest key candidate: %q", got)
	}
}

func TestRuntimeCryptoBlobDoesNotAssumeECBWhenModeUnknown(t *testing.T) {
	content := string(browserRuntimeCryptoBlobContent(browserRuntimeEvent{
		Kind:   "cryptojs_aes",
		Method: "CryptoJS.AES.encrypt",
		Key:    browserRuntimeValue{Type: "string", Value: "SyntK3y!"},
	}, nil))
	if strings.Contains(content, "CryptoJS.mode.ECB") {
		t.Fatalf("unknown mode should not be rendered as ECB:\n%s", content)
	}
}

func TestBrowserRuntimeCaptureWithInstalledChrome(t *testing.T) {
	if os.Getenv("LEAKLENS_TEST_BROWSER_CAPTURE") != "1" {
		t.Skip("set LEAKLENS_TEST_BROWSER_CAPTURE=1 to run browser-backed smoke test")
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<script src="/assets/app.js"></script>`)
		case "/assets/app.js":
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprint(w, `
window.CryptoJS = {
  enc: {Utf8: {parse(value) { return {sigBytes: value.length, toString() { return value; }}; }}},
  mode: {ECB: {}},
  pad: {Pkcs7: {}},
  AES: {encrypt(data, key, options) { return {toString() { return "U3ludGhldGljQ2lwaGVy"; }}; }}
};
localStorage.setItem("REACT_APP_SYNTHETIC_KEY", "SyntValue42");
fetch("/config/runtime.json");
const key = CryptoJS.enc.Utf8.parse("SyntK3y!");
CryptoJS.AES.encrypt("P4ssw0rd!", key, {mode: CryptoJS.mode.ECB, padding: CryptoJS.pad.Pkcs7});
`)
		case "/config/runtime.json":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"runtimeSecret":"SyntRuntime42"}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	enumerator := NewCrawlEnumerator(CrawlConfig{
		TargetURL:      server.URL,
		Timeout:        10 * time.Second,
		BrowserCapture: true,
	})
	result, err := defaultRunBrowserRuntimeCapture(context.Background(), enumerator)
	if err != nil {
		t.Fatalf("browser runtime capture failed: %v", err)
	}
	joinedURLs := strings.Join(result.URLs, "\n")
	if !strings.Contains(joinedURLs, "/assets/app.js") || !strings.Contains(joinedURLs, "/config/runtime.json") {
		t.Fatalf("browser capture missed dynamic URLs:\n%s", joinedURLs)
	}
	var joinedBlobs strings.Builder
	for _, blob := range result.Blobs {
		joinedBlobs.Write(blob.Content)
		joinedBlobs.WriteByte('\n')
	}
	for _, want := range []string{"SyntK3y!", "SyntValue42", "SyntRuntime42"} {
		if !strings.Contains(joinedBlobs.String(), want) {
			t.Fatalf("browser capture missed %q in blobs:\n%s", want, joinedBlobs.String())
		}
	}
}
