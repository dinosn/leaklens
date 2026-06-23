package matcher

import (
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
	default:
		return false
	}

	if len(match.Groups) == 0 {
		return false
	}

	return isGenericPasswordUIPrompt(string(match.Groups[0]))
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
