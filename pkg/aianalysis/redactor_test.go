package aianalysis

import (
	"strings"
	"testing"
)

func TestRedactorAlwaysRedactsTargetURLInExpandedMode(t *testing.T) {
	redactor := NewRedactor(CloudRedactionExpanded, []string{"https://www.example.test/app/"})

	got := redactor.RedactContent(`fetch("https://www.example.test/api/admin?debug=true")`)

	if strings.Contains(got, "example.test") {
		t.Fatalf("target hostname was not redacted: %s", got)
	}
	if !strings.Contains(got, "TARGET_ORIGIN_1/api/admin") {
		t.Fatalf("expected target origin placeholder preserving path, got: %s", got)
	}
}

func TestRedactorStandardRedactsHighEntropyButExpandedKeepsIt(t *testing.T) {
	input := `const publicConfig = "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdef";`

	standard := NewRedactor(CloudRedactionStandard, nil).RedactContent(input)
	if !strings.Contains(standard, "HIGH_ENTROPY_VALUE_REDACTED_LEN_") {
		t.Fatalf("expected standard mode to redact high entropy value, got: %s", standard)
	}

	expanded := NewRedactor(CloudRedactionExpanded, nil).RedactContent(input)
	if !strings.Contains(expanded, "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdef") {
		t.Fatalf("expected expanded mode to preserve generic high entropy context, got: %s", expanded)
	}
}

func TestRedactorExpandedStillRedactsObviousSecret(t *testing.T) {
	got := NewRedactor(CloudRedactionExpanded, nil).RedactContent(`const apiKey = "dummy_secret_value_for_redaction_tests";`)

	if strings.Contains(got, "dummy_secret_value_for_redaction_tests") {
		t.Fatalf("expected obvious secret to be redacted in expanded mode, got: %s", got)
	}
	if !strings.Contains(got, "SECRET_CANDIDATE_") {
		t.Fatalf("expected secret placeholder, got: %s", got)
	}
}
