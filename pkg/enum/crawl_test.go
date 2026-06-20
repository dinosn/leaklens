package enum

import (
	"reflect"
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
