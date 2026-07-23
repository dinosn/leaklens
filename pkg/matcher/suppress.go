package matcher

import (
	"bytes"
	"math"
	"strconv"
	"strings"
	"unicode"

	"github.com/dinosn/leaklens/pkg/types"
)

func shouldSuppressMatch(match *types.Match, content []byte) bool {
	if match == nil {
		return false
	}

	switch match.RuleID {
	case "np.generic.5", "np.generic.6":
		if len(match.Groups) == 0 {
			return false
		}
		return isGenericPasswordUIPrompt(string(match.Groups[0])) ||
			isInputTypeTranslationLabel(match, content)
	case "np.linkedin.3":
		return !hasLinkedInAccessTokenContext(match, content)
	case "leaklens.http.query-secret.1", "leaklens.http.api-key-header.1":
		value := match.NamedGroups["token"]
		if len(value) == 0 && len(match.Groups) > 0 {
			value = match.Groups[0]
		}
		return !isLikelyOpaqueSecretCandidate(string(value))
	default:
		return false
	}
}

func isInputTypeTranslationLabel(match *types.Match, content []byte) bool {
	if len(match.Groups) == 0 || !isShortLetterLabel(normalizePromptCandidate(string(match.Groups[0]))) {
		return false
	}

	context := strings.ToLower(string(matchContextWindow(match, content, 512)))
	context = strings.NewReplacer(
		" ", "", "\t", "", "\r", "", "\n", "", `"`, "", `'`, "",
	).Replace(context)
	markers := []string{
		"color:", "date:", "email:", "month:", "number:", "range:",
		"tel:", "text:", "time:", "url:", "week:",
	}
	count := 0
	for _, marker := range markers {
		if strings.Contains(context, marker) {
			count++
		}
	}
	return count >= 6
}

func isShortLetterLabel(value string) bool {
	if value == "" || len([]rune(value)) > 32 {
		return false
	}
	for _, r := range value {
		if !unicode.IsLetter(r) {
			return false
		}
	}
	return true
}

func hasLinkedInAccessTokenContext(match *types.Match, content []byte) bool {
	token := string(match.NamedGroups["access_token"])
	if token == "" || len(token) > 512 {
		return false
	}

	start := int(match.Location.Offset.Start)
	end := int(match.Location.Offset.End)
	if isBareTokenLine(content, start, end, token) {
		return true
	}

	before := strings.ToLower(string(matchContextBefore(match, content, 256)))
	if strings.Contains(before, "linkedin") {
		return true
	}
	if strings.Contains(before, "authorization") && strings.Contains(before, "bearer") {
		return true
	}
	return containsAny(before, []string{"access_token", "access-token", "accesstoken"})
}

func isBareTokenLine(content []byte, start, end int, token string) bool {
	const radius = 128
	if len(content) == 0 || start < 0 || end < start || end > len(content) {
		return false
	}

	prefixStart := start - radius
	if prefixStart < 0 {
		prefixStart = 0
	}
	prefix := content[prefixStart:start]
	lineStart := prefixStart
	if offset := bytes.LastIndexByte(prefix, '\n'); offset >= 0 {
		lineStart = prefixStart + offset + 1
	} else if prefixStart > 0 {
		return false
	}

	suffixEnd := end + radius
	if suffixEnd > len(content) {
		suffixEnd = len(content)
	}
	lineEnd := suffixEnd
	if offset := bytes.IndexByte(content[end:suffixEnd], '\n'); offset >= 0 {
		lineEnd = end + offset
	} else if suffixEnd < len(content) {
		return false
	}

	line := strings.Trim(strings.TrimSpace(string(content[lineStart:lineEnd])), `"'`+"`;,")
	return line == token
}

func matchContextWindow(match *types.Match, content []byte, radius int) []byte {
	if len(content) == 0 {
		before := match.Snippet.Before
		after := match.Snippet.After
		if len(before) > radius {
			before = before[len(before)-radius:]
		}
		if len(after) > radius {
			after = after[:radius]
		}
		window := make([]byte, 0, len(before)+len(match.Snippet.Matching)+len(after))
		window = append(window, before...)
		window = append(window, match.Snippet.Matching...)
		return append(window, after...)
	}

	start := int(match.Location.Offset.Start) - radius
	end := int(match.Location.Offset.End) + radius
	if start < 0 {
		start = 0
	}
	if end > len(content) {
		end = len(content)
	}
	if start > end {
		return nil
	}
	return content[start:end]
}

func matchContextBefore(match *types.Match, content []byte, radius int) []byte {
	if len(content) == 0 {
		before := match.Snippet.Before
		if len(before) > radius {
			before = before[len(before)-radius:]
		}
		return before
	}
	end := int(match.Location.Offset.Start)
	if end < 0 || end > len(content) {
		return nil
	}
	start := end - radius
	if start < 0 {
		start = 0
	}
	return content[start:end]
}

func isLikelyOpaqueSecretCandidate(value string) bool {
	value = strings.TrimRight(strings.TrimSpace(value), "=")
	if len(value) < 12 || len(value) > 256 {
		return false
	}

	unique := make(map[byte]struct{}, len(value))
	hasLetter := false
	hasDigit := false
	counts := make(map[byte]float64, len(value))
	for i := 0; i < len(value); i++ {
		char := value[i]
		unique[char] = struct{}{}
		counts[char]++
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') {
			hasLetter = true
		}
		if char >= '0' && char <= '9' {
			hasDigit = true
		}
	}
	if !hasLetter || !hasDigit || len(unique) < 6 {
		return false
	}

	lower := strings.ToLower(value)
	compact := strings.NewReplacer("_", "", "-", "", ".", "").Replace(lower)
	for _, marker := range []string{
		"example",
		"sample",
		"dummy",
		"placeholder",
		"changeme",
		"replace",
		"insert",
		"yourtoken",
		"yourapitoken",
		"yourapikey",
		"tokenhere",
	} {
		if strings.Contains(compact, marker) {
			return false
		}
	}

	length := float64(len(value))
	entropy := 0.0
	for _, count := range counts {
		probability := count / length
		entropy -= probability * math.Log2(probability)
	}
	return entropy >= 3.0
}

func isGenericPasswordUIPrompt(value string) bool {
	normalized := normalizePromptCandidate(value)
	if normalized == "" {
		return false
	}

	if containsAny(normalized, []string{"密码", "口令"}) {
		return containsAny(normalized, []string{
			"请输入",
			"请填写",
			"请设置",
			"请确认",
			"输入",
			"填写",
			"不能为空",
			"不正确",
			"错误",
			"不一致",
			"确认密码",
			"登录密码",
			"忘记密码",
			"修改密码",
			"重置密码",
		})
	}

	lower := strings.ToLower(normalized)
	if !strings.Contains(lower, "password") {
		return false
	}

	return containsAny(lower, []string{
		"please",
		"enter",
		"input",
		"required",
		"confirm",
		"forgot",
		"forget",
		"reset",
		"change",
		"placeholder",
		"label",
		"repeat",
	})
}

func normalizePromptCandidate(value string) string {
	trimmed := strings.TrimSpace(value)
	if strings.Contains(trimmed, `\u`) || strings.Contains(trimmed, `\U`) {
		if decoded, err := strconv.Unquote(`"` + strings.ReplaceAll(trimmed, `"`, `\"`) + `"`); err == nil {
			trimmed = decoded
		}
	}
	return strings.Trim(trimmed, " \t\r\n\"'`“”‘’:：.!！?？。；;")
}

func containsAny(value string, candidates []string) bool {
	for _, candidate := range candidates {
		if strings.Contains(value, candidate) {
			return true
		}
	}
	return false
}
