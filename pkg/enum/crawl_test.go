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
