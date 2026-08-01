package enum

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dinosn/leaklens/pkg/types"
	"github.com/projectdiscovery/katana/pkg/navigation"
	katanaoutput "github.com/projectdiscovery/katana/pkg/output"
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
    <script>Ext.manifest = "app.json";</script>
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
		server.URL + "/app/app.json",
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

func TestCrawlInitialPageContentIsRetainedForScanning(t *testing.T) {
	const page = `<!doctype html><script>const config={clientSecret:"Q7vN2mX9pR4sL8kD6wT3"};</script>`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, page)
	}))
	defer server.Close()

	enumerator := NewCrawlEnumerator(CrawlConfig{
		TargetURL:  server.URL,
		Extensions: []string{"js", "json"},
		Scope:      "fqdn",
	})

	discovery, err := enumerator.discoverInitialPage(context.Background())
	if err != nil {
		t.Fatalf("discovering initial page: %v", err)
	}
	if discovery.URL != server.URL {
		t.Fatalf("unexpected initial page URL: %q", discovery.URL)
	}
	if string(discovery.Content) != page {
		t.Fatalf("initial page content was not retained: %q", discovery.Content)
	}
}

func TestCrawlNestedJSONAssetDiscoveryFindsExtJSBundles(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/app.json":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"js":[{"path":"app.js"},{"path":"runtime.js"}],"css":[{"path":"theme.css"}]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	enumerator := NewCrawlEnumerator(CrawlConfig{
		TargetURL:  server.URL,
		Extensions: []string{"js", "json"},
		Scope:      "fqdn",
	})

	got := enumerator.discoverNestedJSONAssetURLs(context.Background(), []string{server.URL + "/app.json"})
	sort.Strings(got)
	want := []string{server.URL + "/app.js", server.URL + "/runtime.js"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected nested JSON assets:\n got: %#v\nwant: %#v", got, want)
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

func TestExtractAssetManifestURLsFindsManifestEntries(t *testing.T) {
	base, err := url.Parse("https://app.example.test/asset-manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{
		"files": {
			"static/js/0.11111111.chunk.js": "/static/js/0.11111111.chunk.js",
			"main.js": "/static/js/main.22222222.chunk.js",
			"runtime-main.js": "/static/js/runtime-main.33333333.js",
			"main.css": "/static/css/main.44444444.chunk.css",
			"static/js/app.55555555.js.map": "/static/js/app.55555555.js.map"
		},
		"entrypoints": [
			"static/js/3.66666666.chunk.js",
			"static/css/main.44444444.chunk.css"
		]
	}`)

	got := extractAssetManifestURLs(base, body, []string{"js", "json", "map"})
	sort.Strings(got)
	want := []string{
		"https://app.example.test/static/js/0.11111111.chunk.js",
		"https://app.example.test/static/js/3.66666666.chunk.js",
		"https://app.example.test/static/js/app.55555555.js.map",
		"https://app.example.test/static/js/main.22222222.chunk.js",
		"https://app.example.test/static/js/runtime-main.33333333.js",
	}
	sort.Strings(want)

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected asset-manifest URLs:\n got: %#v\nwant: %#v", got, want)
	}
	for _, rawURL := range got {
		if strings.HasSuffix(rawURL, "/main.js") {
			t.Fatalf("friendly manifest key should not be treated as an asset URL: %s", rawURL)
		}
	}
}

func TestDiscoverAssetManifestURLsProbesRootManifest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/asset-manifest.json":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{
				"files": {
					"main.js": "/static/js/main.22222222.chunk.js",
					"runtime-main.js": "/static/js/runtime-main.33333333.js"
				},
				"entrypoints": ["static/js/3.66666666.chunk.js"]
			}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	enumerator := NewCrawlEnumerator(CrawlConfig{
		TargetURL:  server.URL + "/nested/page",
		Extensions: []string{"js", "json"},
		Scope:      "fqdn",
	})

	got := enumerator.discoverAssetManifestURLs(context.Background())
	sort.Strings(got)
	want := []string{
		server.URL + "/asset-manifest.json",
		server.URL + "/static/js/3.66666666.chunk.js",
		server.URL + "/static/js/main.22222222.chunk.js",
		server.URL + "/static/js/runtime-main.33333333.js",
	}
	sort.Strings(want)

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected asset-manifest discovery URLs:\n got: %#v\nwant: %#v", got, want)
	}
}

func TestNewCrawlEnumeratorDefaultExtensionsIncludeSourceMaps(t *testing.T) {
	enumerator := NewCrawlEnumerator(CrawlConfig{TargetURL: "https://app.example.test/"})
	want := []string{"js", "json", "map"}

	if !reflect.DeepEqual(enumerator.Extensions, want) {
		t.Fatalf("unexpected default crawl extensions:\n got: %#v\nwant: %#v", enumerator.Extensions, want)
	}
}

func TestShouldRunPostCrawlDiscoveryStopsAfterTimeout(t *testing.T) {
	if shouldRunPostCrawlDiscovery(context.Background(), true, true) {
		t.Fatal("post-crawl discovery should stop after crawl timeout")
	}
	if shouldRunPostCrawlDiscovery(context.Background(), false, false) {
		t.Fatal("post-crawl discovery should stop when feature is disabled")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if shouldRunPostCrawlDiscovery(ctx, false, true) {
		t.Fatal("post-crawl discovery should stop after context cancellation")
	}
	if !shouldRunPostCrawlDiscovery(context.Background(), false, true) {
		t.Fatal("post-crawl discovery should run before timeout while enabled")
	}
}

func TestExtractJSAssetURLsFindsWebpackRuntimeChunks(t *testing.T) {
	base, err := url.Parse("https://app.example.test/static/js/main.11111111.js")
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`n.p="/",n.u=e=>"static/js/"+e+"."+{196:"22222222",257:"33333333"}[e]+".chunk.js"`)

	got := extractJSAssetURLs(base, body, []string{"js", "json"})
	sort.Strings(got)
	want := []string{
		"https://app.example.test/static/js/196.22222222.chunk.js",
		"https://app.example.test/static/js/257.33333333.chunk.js",
	}
	sort.Strings(want)

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected JS asset URLs:\n got: %#v\nwant: %#v", got, want)
	}
}

func TestExtractJSAssetURLsFindsExternalSourceMapReference(t *testing.T) {
	base, err := url.Parse("https://app.example.test/static/js/app.11111111.js")
	if err != nil {
		t.Fatal(err)
	}
	body := []byte("console.log('app');\n//# sourceMappingURL=app.11111111.js.map")

	got := extractJSAssetURLs(base, body, []string{"js", "json", "map"})
	want := []string{"https://app.example.test/static/js/app.11111111.js.map"}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected JS asset URLs:\n got: %#v\nwant: %#v", got, want)
	}
}

func TestDiscoverSourceMapAssetURLsProbesSiblingMap(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/static/js/app.11111111.js.map":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"version":3,"sources":["src/app.js"],"sourcesContent":["const key = \"test\";"]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	enumerator := NewCrawlEnumerator(CrawlConfig{
		TargetURL:  server.URL + "/",
		Extensions: []string{"js", "json", "map"},
		Scope:      "fqdn",
	})

	got := enumerator.discoverSourceMapAssetURLs(context.Background(), []string{server.URL + "/static/js/app.11111111.js"})
	want := []string{server.URL + "/static/js/app.11111111.js.map"}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected source map URLs:\n got: %#v\nwant: %#v", got, want)
	}
}

func TestDiscoverNestedJSAssetURLsFindsWebpackRuntimeChunks(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/static/js/main.b0f8bbd9.js":
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprint(w, `n.p="/",n.u=e=>"static/js/"+e+"."+{314:"44444444",628:"55555555"}[e]+".chunk.js"`)
		case "/static/js/314.44444444.chunk.js", "/static/js/628.55555555.chunk.js":
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprint(w, `console.log("chunk")`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	enumerator := NewCrawlEnumerator(CrawlConfig{
		TargetURL:  server.URL + "/",
		Extensions: []string{"js", "json"},
		Scope:      "fqdn",
	})

	got := enumerator.discoverNestedJSAssetURLs(context.Background(), []string{server.URL + "/static/js/main.b0f8bbd9.js"})
	sort.Strings(got)
	want := []string{
		server.URL + "/static/js/314.44444444.chunk.js",
		server.URL + "/static/js/628.55555555.chunk.js",
	}
	sort.Strings(want)

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected nested JS asset URLs:\n got: %#v\nwant: %#v", got, want)
	}
}

func TestNormalizeDiscoveredAssetURLRepairsEncodedBackslashHostPath(t *testing.T) {
	got := normalizeDiscoveredAssetURL(`https://app.example.test:443/%5C%5C%5C/app.example.test%5C%5C%5C/build%5C%5C%5C/assets%5C%5C%5C/locale-a1b2c3d4.js`)
	want := "https://app.example.test/build/assets/locale-a1b2c3d4.js"

	if got != want {
		t.Fatalf("unexpected normalized URL:\n got: %s\nwant: %s", got, want)
	}
}

func TestExtractJSAssetURLsRepairsEscapedHostPathAndSkipsProse(t *testing.T) {
	base, err := url.Parse("https://app.example.test/assets/js/library.min.js")
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`const files=["\\\/app.example.test\\\/build\\\/assets\\\/locale-a1b2c3d4.js","Widget requires helper.js","\\/build\\/assets\\/real.js"];`)

	got := extractJSAssetURLs(base, body, []string{"js", "json"})
	sort.Strings(got)
	want := []string{
		"https://app.example.test/build/assets/locale-a1b2c3d4.js",
		"https://app.example.test/build/assets/real.js",
	}
	sort.Strings(want)

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected JS asset URLs:\n got: %#v\nwant: %#v", got, want)
	}
}

func TestExtractJSAssetURLsRepairsDuplicatedRelativeAssetDirAndSkipsTemplates(t *testing.T) {
	base, err := url.Parse("https://app.example.test/build/assets/app-a1b2c3d4.js")
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`const files=["assets/vendor_framework-b2c3d4e5.js","/lang/${p}.json","${e}/data.json"];`)

	got := extractJSAssetURLs(base, body, []string{"js", "json"})
	want := []string{"https://app.example.test/build/assets/vendor_framework-b2c3d4e5.js"}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected JS asset URLs:\n got: %#v\nwant: %#v", got, want)
	}
}

func TestCrawlDoesNotRecurseThroughSPAFallbackHTML(t *testing.T) {
	const entryHTML = `<!doctype html><html><head><script src="assets/main.js"></script></head></html>`

	var mu sync.Mutex
	var requestedPaths []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requestedPaths = append(requestedPaths, r.URL.Path)
		mu.Unlock()

		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprint(w, entryHTML)
		case "/assets/main.js":
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprint(w, `const lazyChunk = "missing.js";`)
		default:
			// Include a path marker so Katana's own whole-body deduplication does
			// not hide the failure mode this LeakLens guard must stop. Real SPA
			// fallbacks may vary by nonce, request ID, or injected path.
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprintf(w, "%s<!-- %s -->", entryHTML, r.URL.Path)
		}
	}))
	defer server.Close()

	var logs bytes.Buffer
	restore := SetLogOutput(&logs)
	defer restore()

	enumerator := NewCrawlEnumerator(CrawlConfig{
		TargetURL:      server.URL + "/",
		MaxDepth:       8,
		Concurrency:    1,
		Timeout:        3 * time.Second,
		JSCrawl:        true,
		Extensions:     []string{"js"},
		Scope:          "fqdn",
		MaxDomainPages: 40,
		BrowserCapture: false,
	})

	err := enumerator.Enumerate(context.Background(), func(content []byte, blobID types.BlobID, prov types.Provenance) error {
		return nil
	})
	if err != nil {
		t.Fatalf("crawl failed: %v", err)
	}

	mu.Lock()
	paths := append([]string(nil), requestedPaths...)
	mu.Unlock()
	for _, requestedPath := range paths {
		if hasExcessivePathSegmentRepetition(requestedPath, 2) {
			t.Fatalf("SPA fallback recursion reached repeated path %q; requests: %#v", requestedPath, paths)
		}
	}
	if got := logs.String(); !strings.Contains(got, "probable SPA fallback recursion") {
		t.Fatalf("expected a loud SPA fallback warning; requests: %#v; logs: %s", paths, got)
	}
}

func TestFetchJSAssetForDiscoveryRejectsHTML(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<!doctype html><script src="assets/main.js"></script>`)
	}))
	defer server.Close()

	_, _, err := fetchJSAssetForDiscovery(context.Background(), server.Client(), server.URL+"/missing.js", 1<<20)
	if err == nil {
		t.Fatal("expected HTML returned for a .js URL to be rejected")
	}
}

func TestNestedJSDiscoveryStopsAtSPAFallbackHTML(t *testing.T) {
	const entryHTML = `<!doctype html><script src="assets/main.js"></script>`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/assets/main.js" {
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprint(w, `const lazyChunk = "missing.js";`)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, entryHTML)
	}))
	defer server.Close()

	var logs bytes.Buffer
	restore := SetLogOutput(&logs)
	defer restore()

	enumerator := NewCrawlEnumerator(CrawlConfig{
		TargetURL:  server.URL + "/",
		Extensions: []string{"js"},
		Scope:      "fqdn",
	})
	got := enumerator.discoverNestedJSAssetURLs(context.Background(), []string{server.URL + "/assets/main.js"})
	if len(got) != 0 {
		t.Fatalf("HTML fallback remained a nested asset candidate: %#v", got)
	}
	if output := logs.String(); !strings.Contains(output, "probable SPA fallback recursion") {
		t.Fatalf("expected SPA fallback warning, got logs: %s", output)
	}
}

func TestHasExcessivePathSegmentRepetition(t *testing.T) {
	tests := []struct {
		name   string
		rawURL string
		want   bool
	}{
		{name: "two repetitions allowed", rawURL: "https://app.example.test/static/js/static/config.js", want: false},
		{name: "third nonconsecutive repetition rejected", rawURL: "https://app.example.test/static/js/vendor/static/chunks/static/config.js", want: true},
		{name: "third encoded repetition rejected", rawURL: "https://app.example.test/static%2Fjs%2Fstatic%2Fjs%2Fstatic%2Fconfig.js", want: true},
		{name: "query ignored", rawURL: "https://app.example.test/assets/main.js?next=/assets/assets/assets", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hasExcessivePathSegmentRepetition(tt.rawURL, 2); got != tt.want {
				t.Fatalf("hasExcessivePathSegmentRepetition(%q, 2) = %v, want %v", tt.rawURL, got, tt.want)
			}
		})
	}
}

func TestCrawlSanityGuardSuppressesEntryHTMLAtAssetURL(t *testing.T) {
	const entryURL = "https://app.example.test/"
	body := []byte(`<!doctype html><script src="/assets/main.js"></script>`)
	guard := newCrawlSanityGuard(1000)
	guard.setEntry(entryURL, body)

	httpRequest, err := http.NewRequest(http.MethodGet, "https://app.example.test/assets/missing.js", nil)
	if err != nil {
		t.Fatal(err)
	}
	result := katanaoutput.Result{
		Request: &navigation.Request{URL: httpRequest.URL.String()},
		Response: &navigation.Response{
			Body: string(body),
			Resp: &http.Response{
				Header:  http.Header{"Content-Type": []string{"text/html; charset=utf-8"}},
				Request: httpRequest,
			},
		},
	}

	suppress, reason, shouldWarn := guard.shouldSuppressResult(result, []string{"js"})
	if !suppress || !shouldWarn {
		t.Fatalf("expected entry-HTML asset response to be suppressed with a warning, got suppress=%v warn=%v", suppress, shouldWarn)
	}
	if !strings.Contains(reason, "byte-identical to the entry HTML") {
		t.Fatalf("unexpected suppression reason: %q", reason)
	}
	suppressCrawlResultExpansion(result)
	if result.Response.Resp != nil || result.Response.Reader != nil || result.Response.Body != "" {
		t.Fatalf("suppressed result remained parseable: %#v", result.Response)
	}
}

func TestCrawlSanityGuardDiscoveryCap(t *testing.T) {
	guard := newCrawlSanityGuard(2)
	for _, rawURL := range []string{
		"https://app.example.test/assets/one.js",
		"https://app.example.test/assets/two.js",
	} {
		allowed, reason, shouldWarn := guard.allowDiscovery(rawURL)
		if !allowed || reason != "" || shouldWarn {
			t.Fatalf("expected discovery below cap to be allowed: allowed=%v reason=%q warn=%v", allowed, reason, shouldWarn)
		}
	}

	allowed, reason, shouldWarn := guard.allowDiscovery("https://app.example.test/assets/three.js")
	if allowed || !shouldWarn {
		t.Fatalf("expected third discovery to hit cap with warning: allowed=%v warn=%v", allowed, shouldWarn)
	}
	if !strings.Contains(reason, "cap hit") || !strings.Contains(reason, "probable fallback recursion") {
		t.Fatalf("unexpected cap reason: %q", reason)
	}
}
