package matcher

import (
	"math"
	"strconv"
	"strings"

	"github.com/dinosn/leaklens/pkg/types"
)

func shouldSuppressMatch(match *types.Match) bool {
	if match == nil {
		return false
	}

	switch match.RuleID {
	case "np.generic.5", "np.generic.6":
		if len(match.Groups) == 0 {
			return false
		}
		return isGenericPasswordUIPrompt(string(match.Groups[0]))
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
