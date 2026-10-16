package matcher

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/dinosn/leaklens/pkg/types"
)

const defaultSpecialCharacters = "!@#$%^&*()_+-=[]{}|;:'\",.<>?/\\`~"

func shouldSuppressMatch(rule *types.Rule, match *types.Match, content []byte) bool {
	if match == nil {
		return false
	}

	candidate := matchSecretCandidate(match)
	if isTemplatePlaceholder(string(candidate)) || failsRuleMatchPolicy(rule, match, candidate) {
		return true
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
	case "leaklens.js.client-secret.1":
		value := match.NamedGroups["client_secret"]
		if len(value) == 0 && len(match.Groups) > 0 {
			value = match.Groups[len(match.Groups)-1]
		}
		return !isLikelyClientSecretCandidate(string(value))
	case "leaklens.js.api-secret.1":
		value := match.NamedGroups["api_secret"]
		if len(value) == 0 && len(match.Groups) > 0 {
			value = match.Groups[len(match.Groups)-1]
		}
		return !isLikelyAPISecretCandidate(string(value))
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

func failsRuleMatchPolicy(rule *types.Rule, match *types.Match, candidate []byte) bool {
	if rule == nil {
		return false
	}
	if rule.MinEntropy > 0 && shannonEntropy(candidate) <= rule.MinEntropy {
		return true
	}

	requirements := rule.PatternRequirements
	if requirements == nil {
		return false
	}

	policyInput := candidate
	if match.HasNamedGroups || match.CaptureGroupCount > 1 ||
		len(match.NamedGroups) > 0 || len(match.Groups) > 1 {
		policyInput = match.Snippet.Matching
	}
	value := string(policyInput)

	if requirements.MinDigits != nil && countASCII(value, isASCIIDigit) < *requirements.MinDigits {
		return true
	}
	if requirements.MinUppercase != nil && countASCII(value, isASCIIUpper) < *requirements.MinUppercase {
		return true
	}
	if requirements.MinLowercase != nil && countASCII(value, isASCIILower) < *requirements.MinLowercase {
		return true
	}
	if requirements.MinSpecialChars != nil {
		specialCharacters := defaultSpecialCharacters
		if requirements.SpecialChars != nil {
			specialCharacters = *requirements.SpecialChars
		}
		count := 0
		for _, char := range value {
			if strings.ContainsRune(specialCharacters, char) {
				count++
			}
		}
		if count < *requirements.MinSpecialChars {
			return true
		}
	}

	lower := strings.ToLower(value)
	for _, ignored := range requirements.IgnoreIfContains {
		ignored = strings.TrimSpace(ignored)
		if ignored != "" && strings.Contains(lower, strings.ToLower(ignored)) {
			return true
		}
	}

	if requirements.Checksum != nil && !checksumRequirementPasses(requirements.Checksum, match, value) {
		return true
	}
	return false
}

func matchSecretCandidate(match *types.Match) []byte {
	if len(match.SecretValue) > 0 {
		return match.SecretValue
	}
	for name, value := range match.NamedGroups {
		if strings.EqualFold(name, "token") && len(value) > 0 {
			return value
		}
	}

	if len(match.NamedGroups) > 0 {
		names := make([]string, 0, len(match.NamedGroups))
		for name := range match.NamedGroups {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			if value := match.NamedGroups[name]; len(value) > 0 {
				return value
			}
		}
	}
	if len(match.Groups) > 0 {
		return match.Groups[0]
	}
	return match.Snippet.Matching
}

func isTemplatePlaceholder(value string) bool {
	value = strings.TrimSpace(value)
	if len(value) < 4 {
		return false
	}
	return (strings.HasPrefix(value, "${") && strings.HasSuffix(value, "}")) ||
		(strings.HasPrefix(value, "{{") && strings.HasSuffix(value, "}}")) ||
		(strings.HasPrefix(value, "<%=") && strings.HasSuffix(value, "%>"))
}

func shannonEntropy(value []byte) float64 {
	if len(value) == 0 {
		return 0
	}
	counts := make(map[byte]float64, len(value))
	for _, char := range value {
		counts[char]++
	}
	length := float64(len(value))
	entropy := 0.0
	for _, count := range counts {
		probability := count / length
		entropy -= probability * math.Log2(probability)
	}
	return entropy
}

func countASCII(value string, predicate func(rune) bool) int {
	count := 0
	for _, char := range value {
		if predicate(char) {
			count++
		}
	}
	return count
}

func isASCIIDigit(char rune) bool { return char >= '0' && char <= '9' }
func isASCIIUpper(char rune) bool { return char >= 'A' && char <= 'Z' }
func isASCIILower(char rune) bool { return char >= 'a' && char <= 'z' }

func checksumRequirementPasses(requirement *types.ChecksumRequirement, match *types.Match, policyInput string) bool {
	if requirement == nil {
		return true
	}
	if required := requirement.Actual.RequiresCapture; required != "" {
		if _, ok := match.NamedGroups[required]; !ok {
			return requirement.SkipIfMissing
		}
	}

	actual, actualOK := renderChecksumTemplate(requirement.Actual.Template, match, policyInput)
	expected, expectedOK := renderChecksumTemplate(requirement.Expected, match, policyInput)
	if !actualOK || !expectedOK {
		// An unsupported custom checksum template must not hide a finding.
		return true
	}
	return actual == expected
}

func renderChecksumTemplate(template string, match *types.Match, policyInput string) (string, bool) {
	template = strings.TrimSpace(template)
	if !strings.HasPrefix(template, "{{") || !strings.HasSuffix(template, "}}") {
		return "", false
	}
	parts := strings.Split(strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(template, "{{"), "}}")), "|")
	if len(parts) == 0 {
		return "", false
	}

	value, ok := checksumTemplateVariable(strings.TrimSpace(parts[0]), match, policyInput)
	if !ok {
		return "", false
	}
	for _, rawFilter := range parts[1:] {
		filterParts := strings.SplitN(strings.TrimSpace(rawFilter), ":", 2)
		name := strings.TrimSpace(filterParts[0])
		argument := -1
		if len(filterParts) == 2 {
			parsed, err := strconv.Atoi(strings.TrimSpace(filterParts[1]))
			if err != nil || parsed < 0 {
				return "", false
			}
			argument = parsed
		}

		switch name {
		case "downcase":
			if argument >= 0 {
				return "", false
			}
			value = strings.ToLower(value)
		case "suffix":
			if argument < 0 {
				return "", false
			}
			runes := []rune(value)
			if argument < len(runes) {
				runes = runes[len(runes)-argument:]
			}
			value = string(runes)
		case "crc32_hex":
			checksum := fmt.Sprintf("%08x", crc32.ChecksumIEEE([]byte(value)))
			if argument > 0 {
				digits := argument
				if digits > 32 {
					digits = 32
				}
				if digits < len(checksum) {
					checksum = checksum[len(checksum)-digits:]
				} else if digits > len(checksum) {
					checksum = strings.Repeat("0", digits-len(checksum)) + checksum
				}
			}
			value = checksum
		case "crc32_le_b64":
			checksum := crc32.ChecksumIEEE([]byte(value))
			var encoded [4]byte
			binary.LittleEndian.PutUint32(encoded[:], checksum)
			value = base64.StdEncoding.EncodeToString(encoded[:])
			if argument >= 0 && argument < len(value) {
				value = value[:argument]
			}
		default:
			return "", false
		}
	}
	return value, true
}

func checksumTemplateVariable(name string, match *types.Match, policyInput string) (string, bool) {
	if strings.EqualFold(name, "MATCH") {
		return policyInput, true
	}
	if strings.EqualFold(name, "FULL_MATCH") {
		return string(match.Snippet.Matching), true
	}
	for captureName, value := range match.NamedGroups {
		if strings.EqualFold(name, captureName) {
			return string(value), true
		}
	}
	return "", false
}

func isLikelyClientSecretCandidate(value string) bool {
	if !isLikelyOpaqueSecretCandidate(value) {
		return false
	}

	compact := strings.NewReplacer("_", "", "-", "", ".", "").Replace(strings.ToLower(value))
	return !containsAny(compact, []string{
		"yourclientsecret",
		"clientsecrethere",
		"testsecret",
		"mocksecret",
		"fakesecret",
		"demosecret",
		"notasecret",
		"secretvalue",
	})
}

func isLikelyAPISecretCandidate(value string) bool {
	if !isLikelyOpaqueSecretCandidateWithMinLength(value, 8) {
		return false
	}

	compact := strings.NewReplacer("_", "", "-", "", ".", "").Replace(strings.ToLower(value))
	return !containsAny(compact, []string{
		"yourapisecret",
		"apisecrethere",
		"testapisecret",
		"mockapisecret",
		"fakeapisecret",
		"demoapisecret",
		"notasecret",
		"secretvalue",
	})
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
	return isLikelyOpaqueSecretCandidateWithMinLength(value, 12)
}

func isLikelyOpaqueSecretCandidateWithMinLength(value string, minLength int) bool {
	value = strings.TrimRight(strings.TrimSpace(value), "=")
	if len(value) < minLength || len(value) > 256 {
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
