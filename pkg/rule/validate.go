package rule

import (
	"fmt"
	"math"
	"regexp"

	"github.com/dinosn/leaklens/pkg/types"
)

// ValidateRule checks rule consistency and required fields.
// Returns error if rule is invalid.
func ValidateRule(r *types.Rule) error {
	if r == nil {
		return fmt.Errorf("rule is nil")
	}

	// Check required fields
	if r.ID == "" {
		return fmt.Errorf("rule ID is required")
	}
	if r.Name == "" {
		return fmt.Errorf("rule name is required")
	}
	if r.Pattern == "" {
		return fmt.Errorf("rule pattern is required")
	}
	if math.IsNaN(r.MinEntropy) || math.IsInf(r.MinEntropy, 0) || r.MinEntropy < 0 {
		return fmt.Errorf("rule %s has invalid min_entropy: %v", r.ID, r.MinEntropy)
	}
	if err := validatePatternRequirements(r.ID, r.PatternRequirements); err != nil {
		return err
	}

	// Validate pattern is a valid regex
	_, err := regexp.Compile(r.Pattern)
	if err != nil {
		return fmt.Errorf("invalid pattern regex for rule %s: %w", r.ID, err)
	}

	// Validate StructuralID matches computed value
	expectedID := r.ComputeStructuralID()
	if r.StructuralID != "" && r.StructuralID != expectedID {
		return fmt.Errorf("rule %s has inconsistent StructuralID: got %s, expected %s",
			r.ID, r.StructuralID, expectedID)
	}

	return nil
}

func validatePatternRequirements(ruleID string, requirements *types.PatternRequirements) error {
	if requirements == nil {
		return nil
	}

	for name, value := range map[string]*int{
		"min_digits":        requirements.MinDigits,
		"min_uppercase":     requirements.MinUppercase,
		"min_lowercase":     requirements.MinLowercase,
		"min_special_chars": requirements.MinSpecialChars,
	} {
		if value != nil && *value < 0 {
			return fmt.Errorf("rule %s has negative %s", ruleID, name)
		}
	}

	if checksum := requirements.Checksum; checksum != nil {
		if checksum.Actual.Template == "" {
			return fmt.Errorf("rule %s checksum actual template is required", ruleID)
		}
		if checksum.Expected == "" {
			return fmt.Errorf("rule %s checksum expected template is required", ruleID)
		}
	}

	return nil
}

// ValidateRuleset checks ruleset consistency and required fields.
// knownRuleIDs is a map of valid rule IDs for reference checking.
// Returns error if ruleset is invalid.
func ValidateRuleset(rs *types.Ruleset, knownRuleIDs map[string]bool) error {
	if rs == nil {
		return fmt.Errorf("ruleset is nil")
	}

	// Check required fields
	if rs.ID == "" {
		return fmt.Errorf("ruleset ID is required")
	}
	if rs.Name == "" {
		return fmt.Errorf("ruleset name is required")
	}
	if len(rs.RuleIDs) == 0 {
		return fmt.Errorf("ruleset %s must reference at least one rule", rs.ID)
	}

	// Validate all referenced rule IDs exist
	if knownRuleIDs != nil {
		for _, ruleID := range rs.RuleIDs {
			if !knownRuleIDs[ruleID] {
				return fmt.Errorf("ruleset %s references unknown rule ID: %s", rs.ID, ruleID)
			}
		}
	}

	// Check for duplicate rule IDs
	seen := make(map[string]bool)
	for _, ruleID := range rs.RuleIDs {
		if seen[ruleID] {
			return fmt.Errorf("ruleset %s contains duplicate rule ID: %s", rs.ID, ruleID)
		}
		seen[ruleID] = true
	}

	return nil
}
