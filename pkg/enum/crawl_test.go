package enum

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestCrawlURLCandidatesRepairDuplicatedScriptPath(t *testing.T) {
	enumerator := NewCrawlEnumerator(CrawlConfig{
		TargetURL: "https://salesapp.example.test/p92/js/salesApp/sso.js",
	})

	got := enumerator.urlCandidates("https://salesapp.example.test/p92/js/salesApp/js/salesApp/login.js")
	want := []string{
		"https://salesapp.example.test/p92/js/salesApp/js/salesApp/login.js",
		"https://salesapp.example.test/p92/js/salesApp/login.js",
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected candidates:\n got: %#v\nwant: %#v", got, want)
	}
}

func TestCrawlURLCandidatesUseExplicitBaseURL(t *testing.T) {
	enumerator := NewCrawlEnumerator(CrawlConfig{
		TargetURL: "https://app.example.test/p92/static/js/main.js",
		BaseURL:   "https://app.example.test/p92/",
	})

	got := enumerator.urlCandidates("https://app.example.test/p92/static/js/api/config.json")
	want := []string{
		"https://app.example.test/p92/static/js/api/config.json",
		"https://app.example.test/p92/api/config.json",
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected candidates:\n got: %#v\nwant: %#v", got, want)
	}
}

func TestCrawlURLCandidatesDoNotRepairCrossHost(t *testing.T) {
	enumerator := NewCrawlEnumerator(CrawlConfig{
		TargetURL: "https://app.example.test/p92/js/salesApp/sso.js",
	})

	got := enumerator.urlCandidates("https://cdn.example.test/p92/js/salesApp/js/salesApp/login.js")
	want := []string{"https://cdn.example.test/p92/js/salesApp/js/salesApp/login.js"}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected candidates:\n got: %#v\nwant: %#v", got, want)
	}
}

func TestShouldUseHeadlessNoSandboxForRootHeadlessLaunch(t *testing.T) {
	got := shouldUseHeadlessNoSandboxForEUID(false, true, "", 0)
	if !got {
		t.Fatal("expected root headless launch to enable no-sandbox")
	}
}

func TestShouldUseHeadlessNoSandboxNotNeededWhenAttachingChrome(t *testing.T) {
	got := shouldUseHeadlessNoSandboxForEUID(false, true, "ws://127.0.0.1:9222/devtools/browser/test", 0)
	if got {
		t.Fatal("expected Chrome websocket attach to avoid no-sandbox auto-enable")
	}
}

func TestShouldUseHeadlessNoSandboxExplicitFlag(t *testing.T) {
	got := shouldUseHeadlessNoSandboxForEUID(true, false, "ws://127.0.0.1:9222/devtools/browser/test", 1000)
	if !got {
		t.Fatal("expected explicit no-sandbox flag to be honored")
	}
}

func TestCrawlInitialHTMLAssetDiscoveryFindsImportmapAndPreloadAssets(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/app/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Add("Link", `</assets/from-link-header-c0ffee01.js>; rel=preload; as=script`)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<!doctype html>
<html>
  <head>
    <script type="importmap">{
      "imports": {
        "application": "/assets/application-b3af3ba5.js",
        "controllers/reports_controller": "/assets/controllers/reports_controller-e3257b8f.js",
        "style": "/assets/application-347a7ab9.css"
      },
      "scopes": {
        "/assets/": {
          "scoped_controller": "/assets/controllers/scoped_controller-11111111.js"
        }
      }
    }</script>
    <link rel="modulepreload" href="/assets/controllers/account_completion_controller-93a905a6.js">
    <link rel="preload" as="script" href="/assets/vendor/jquery.min-6c84fd2b.js">
    <link rel="stylesheet" href="/assets/application-347a7ab9.css">
    <script src="/assets/direct-script-22222222.js"></script>
  </head>
</html>`)
	}))
	defer server.Close()

	enumerator := NewCrawlEnumerator(CrawlConfig{
		TargetURL:  server.URL + "/app/",
		Extensions: []string{"js", "json"},
		Scope:      "fqdn",
	})

	got, err := enumerator.discoverInitialAssetURLs(context.Background())
	if err != nil {
		t.Fatalf("discoverInitialAssetURLs failed: %v", err)
	}
	sort.Strings(got)

	want := []string{
		server.URL + "/assets/application-b3af3ba5.js",
		server.URL + "/assets/controllers/account_completion_controller-93a905a6.js",
		server.URL + "/assets/controllers/reports_controller-e3257b8f.js",
		server.URL + "/assets/controllers/scoped_controller-11111111.js",
		server.URL + "/assets/direct-script-22222222.js",
		server.URL + "/assets/from-link-header-c0ffee01.js",
		server.URL + "/assets/vendor/jquery.min-6c84fd2b.js",
	}
	sort.Strings(want)

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected initial asset URLs:\n got: %#v\nwant: %#v", got, want)
	}
}

func TestCrawlInitialHTMLAssetDiscoveryKeepsScopedURLsInScope(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<script src="https://cdn.example.test/out-of-scope.js"></script><script src="/assets/in-scope.js"></script>`)
	}))
	defer server.Close()

	enumerator := NewCrawlEnumerator(CrawlConfig{
		TargetURL:  server.URL,
		Extensions: []string{"js"},
		Scope:      "fqdn",
	})

	got, err := enumerator.discoverInitialAssetURLs(context.Background())
	if err != nil {
		t.Fatalf("discoverInitialAssetURLs failed: %v", err)
	}
	for _, rawURL := range got {
		if !enumerator.urlInScope(rawURL) {
			t.Fatalf("initial asset discovery returned out-of-scope URL: %s", rawURL)
		}
	}
}

func TestCrawlInitialHTMLAssetDiscoveryRetriesCertificateVerificationFailure(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<script src="/assets/app.js"></script>`)
	}))
	defer server.Close()

	var logs bytes.Buffer
	restore := SetLogOutput(&logs)
	defer restore()

	enumerator := NewCrawlEnumerator(CrawlConfig{
		TargetURL:  server.URL,
		Extensions: []string{"js"},
		Scope:      "fqdn",
	})

	got, err := enumerator.discoverInitialAssetURLs(context.Background())
	if err != nil {
		t.Fatalf("discoverInitialAssetURLs failed: %v", err)
	}

	want := []string{server.URL + "/assets/app.js"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected initial asset URLs:\n got: %#v\nwant: %#v", got, want)
	}
	if !strings.Contains(logs.String(), "TLS certificate verification failed") {
		t.Fatalf("expected TLS verification warning, got logs: %s", logs.String())
	}
}
