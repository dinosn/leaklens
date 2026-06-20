package jsintel

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestAnalyzeExtractsPassiveArtifacts(t *testing.T) {
	content := []byte(`
import axios from "axios";
import fs from "node:fs";
const cdn = "assets.example.com";
const bucket = "app-assets.s3.amazonaws.com/static/app.js";
client.get("/api/v1/users");
fetch("https://api.example.com/v2/orders?token=abc123");
const pkg = "/node_modules/@internal/widget/dist/index.js";
`)

	result := New(DefaultConfig()).Analyze(content, "app.js")

	assertFinding(t, result.Findings, CategoryEndpoint, "/api/v1/users")
	assertFinding(t, result.Findings, CategoryEndpoint, "https://api.example.com/v2/orders?token=abc123")
	assertFinding(t, result.Findings, CategoryCloudURL, "app-assets.s3.amazonaws.com/static/app.js")
	assertFinding(t, result.Findings, CategorySubdomain, "assets.example.com")
	assertFinding(t, result.Findings, CategoryDependency, "@internal/widget")
	assertNoFinding(t, result.Findings, CategoryDependency, "fs")

	for _, f := range result.Findings {
		if f.Value == "https://api.example.com/v2/orders?token=abc123" {
			display := DisplayValue(f)
			if strings.Contains(display, "abc123") {
				t.Fatalf("DisplayValue did not redact sensitive query value: %s", display)
			}
		}
	}
}

func TestAnalyzeExtractsInlineSourceMapSources(t *testing.T) {
	sm := map[string]any{
		"version":        3,
		"sources":        []string{"webpack://src/config.js"},
		"sourcesContent": []string{`const apiToken = "exampleSourceMapSecret12345";`},
	}
	data, err := json.Marshal(sm)
	if err != nil {
		t.Fatal(err)
	}
	content := []byte("console.log('minified');\n//# sourceMappingURL=data:application/json;base64," + base64.StdEncoding.EncodeToString(data))

	result := New(DefaultConfig()).Analyze(content, "bundle.js")

	assertFinding(t, result.Findings, CategorySourceMap, "inline source map")
	if len(result.Sources) != 1 {
		t.Fatalf("expected one source-map source, got %d", len(result.Sources))
	}
	if result.Sources[0].Path != "src/config.js" {
		t.Fatalf("unexpected source path: %s", result.Sources[0].Path)
	}
	if !strings.Contains(string(result.Sources[0].Content), "exampleSourceMapSecret12345") {
		t.Fatalf("source-map content was not preserved: %s", string(result.Sources[0].Content))
	}
}

func TestGenericSecretsAreOptInAndMasked(t *testing.T) {
	content := []byte(`const apiToken = "ZXhhbXBsZVNlY3JldDEyMzQ1";`)

	defaultResult := New(DefaultConfig()).Analyze(content, "app.js")
	for _, f := range defaultResult.Findings {
		if f.Category == CategoryGenericSecretHeuristic {
			t.Fatalf("generic secret heuristic should be disabled by default")
		}
	}

	cfg := DefaultConfig()
	cfg.GenericSecrets = true
	result := New(cfg).Analyze(content, "app.js")

	var generic *Finding
	for i := range result.Findings {
		if result.Findings[i].Category == CategoryGenericSecretHeuristic {
			generic = &result.Findings[i]
			break
		}
	}
	if generic == nil {
		t.Fatalf("expected generic secret heuristic finding")
	}
	if strings.Contains(generic.Value, "Y3JldD") {
		t.Fatalf("generic secret value was not masked: %s", generic.Value)
	}
	if generic.Confidence != "medium" {
		t.Fatalf("expected medium confidence, got %s", generic.Confidence)
	}
}

func TestNPMCheckFlagsMissingDependencies(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestedPath, err := url.PathUnescape(strings.TrimPrefix(r.URL.EscapedPath(), "/"))
		if err != nil {
			t.Fatalf("failed to decode request path: %v", err)
		}
		switch requestedPath {
		case "missing-package", "@internal/widget":
			http.NotFound(w, r)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer server.Close()

	cfg := DefaultConfig()
	cfg.NPMCheck = true
	cfg.NPMRegistryURL = server.URL
	content := []byte(`{"dependencies":{"missing-package":"1.0.0","@internal/widget":"1.0.0","present-package":"1.0.0"}}`)

	result := New(cfg).Analyze(content, "package.json")

	assertFinding(t, result.Findings, CategoryDependencyConfusion, "missing-package")
	assertFinding(t, result.Findings, CategoryDependencyConfusion, "@internal/widget")
	for _, f := range result.Findings {
		if f.Category == CategoryDependencyConfusion && f.Value == "present-package" {
			t.Fatalf("present-package should not be flagged as missing")
		}
	}
}

func assertFinding(t *testing.T, findings []Finding, category Category, value string) {
	t.Helper()
	for _, finding := range findings {
		if finding.Category == category && finding.Value == value {
			return
		}
	}
	t.Fatalf("missing finding %s %q in %#v", category, value, findings)
}

func assertNoFinding(t *testing.T, findings []Finding, category Category, value string) {
	t.Helper()
	for _, finding := range findings {
		if finding.Category == category && finding.Value == value {
			t.Fatalf("unexpected finding %s %q in %#v", category, value, findings)
		}
	}
}
