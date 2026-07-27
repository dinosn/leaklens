package types

import (
	"crypto/sha1"
	"encoding/hex"
	"regexp"
)

// Rule is a detection rule with pattern and metadata.
type Rule struct {
	ID                  string               // e.g., "np.aws.1"
	Name                string               // human-readable name
	Pattern             string               // regex pattern
	StructuralID        string               // SHA-1 of pattern (computed)
	Description         string               // optional
	Examples            []string             // positive test cases
	NegativeExamples    []string             // negative test cases
	References          []string             // documentation URLs
	Categories          []string             // classification tags
	Keywords            []string             // keywords for Aho-Corasick prefiltering
	MinEntropy          float64              `json:"min_entropy,omitempty"`
	PatternRequirements *PatternRequirements `json:"pattern_requirements,omitempty"`
}

// PatternRequirements applies data-driven quality checks after a rule's regex
// matches. The fields mirror the Kingfisher rule corpus used by LeakLens.
type PatternRequirements struct {
	MinDigits        *int                 `yaml:"min_digits,omitempty" json:"min_digits,omitempty"`
	MinUppercase     *int                 `yaml:"min_uppercase,omitempty" json:"min_uppercase,omitempty"`
	MinLowercase     *int                 `yaml:"min_lowercase,omitempty" json:"min_lowercase,omitempty"`
	MinSpecialChars  *int                 `yaml:"min_special_chars,omitempty" json:"min_special_chars,omitempty"`
	SpecialChars     *string              `yaml:"special_chars,omitempty" json:"special_chars,omitempty"`
	IgnoreIfContains []string             `yaml:"ignore_if_contains,omitempty" json:"ignore_if_contains,omitempty"`
	Checksum         *ChecksumRequirement `yaml:"checksum,omitempty" json:"checksum,omitempty"`
}

// ChecksumRequirement describes a checksum comparison for a matched value.
// LeakLens currently supports the checksum templates present in its built-in
// rule corpus.
type ChecksumRequirement struct {
	Actual        ChecksumActual `yaml:"actual" json:"actual"`
	Expected      string         `yaml:"expected" json:"expected"`
	SkipIfMissing bool           `yaml:"skip_if_missing,omitempty" json:"skip_if_missing,omitempty"`
}

// ChecksumActual describes how to extract the checksum embedded in a match.
type ChecksumActual struct {
	Template        string `yaml:"template" json:"template"`
	RequiresCapture string `yaml:"requires_capture,omitempty" json:"requires_capture,omitempty"`
}

// namedGroupRe matches named capture groups like (?P<name>...) and replaces
// them with plain unnamed groups (...) for NoseyParker-compatible hashing.
var namedGroupRe = regexp.MustCompile(`\(\?P<[^>]+>`)

// ComputeStructuralID computes SHA-1 of pattern, normalizing named capture
// groups to unnamed groups for compatibility with NoseyParker's structural IDs.
func (r *Rule) ComputeStructuralID() string {
	normalized := namedGroupRe.ReplaceAllString(r.Pattern, "(")
	h := sha1.New()
	h.Write([]byte(normalized))
	return hex.EncodeToString(h.Sum(nil))
}

// Ruleset groups rules together.
type Ruleset struct {
	ID          string
	Name        string
	Description string
	RuleIDs     []string
}
