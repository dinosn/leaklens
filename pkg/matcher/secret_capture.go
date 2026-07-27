package matcher

import (
	"strings"

	"github.com/dinosn/leaklens/pkg/types"
	"github.com/dlclark/regexp2"
)

func populateMatchPolicyMetadata(result *types.Match, match *regexp2.Match, groupNames []string) {
	if result == nil || match == nil {
		return
	}
	result.SecretValue = extractSecretValue(match, groupNames)
	if groups := match.Groups(); len(groups) > 0 {
		result.CaptureGroupCount = len(groups) - 1
	}
	result.HasNamedGroups = hasNamedCaptures(groupNames)
}

// extractSecretValue mirrors the rule corpus's canonical capture selection:
// TOKEN (case-insensitive), first matched named group, group 1, then group 0.
func extractSecretValue(match *regexp2.Match, groupNames []string) []byte {
	if match == nil {
		return nil
	}

	for _, name := range groupNames {
		if !isNamedCapture(name) || !strings.EqualFold(name, "token") {
			continue
		}
		if value := firstGroupCapture(match.GroupByName(name)); value != nil {
			return value
		}
	}

	for _, name := range groupNames {
		if !isNamedCapture(name) {
			continue
		}
		if value := firstGroupCapture(match.GroupByName(name)); value != nil {
			return value
		}
	}

	groups := match.Groups()
	if len(groups) > 1 {
		if value := firstGroupCapture(&groups[1]); value != nil {
			return value
		}
	}
	if len(groups) > 0 {
		return firstGroupCapture(&groups[0])
	}
	return nil
}

func firstGroupCapture(group *regexp2.Group) []byte {
	if group == nil || len(group.Captures) == 0 {
		return nil
	}
	return []byte(group.Captures[0].String())
}

func isNamedCapture(name string) bool {
	return name != "" && (name[0] < '0' || name[0] > '9')
}

func hasNamedCaptures(groupNames []string) bool {
	for _, name := range groupNames {
		if isNamedCapture(name) {
			return true
		}
	}
	return false
}
