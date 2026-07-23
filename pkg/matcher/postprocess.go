package matcher

import (
	"crypto/aes"
	"encoding/base64"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/dinosn/leaklens/pkg/types"
)

const aesPasswordFlowRuleID = "leaklens.js.crypto.2"

type postProcessingMatcher struct {
	base           Matcher
	rules          map[string]*types.Rule
	contextLines   int
	aesCiphertexts []AESCiphertextEvidence
}

func newPostProcessingMatcher(base Matcher, cfg Config) Matcher {
	rules := make(map[string]*types.Rule, len(cfg.Rules))
	for _, rule := range cfg.Rules {
		rules[rule.ID] = rule
	}
	aesCiphertexts := make([]AESCiphertextEvidence, 0, len(cfg.AESCiphertexts))
	for _, evidence := range cfg.AESCiphertexts {
		aesCiphertexts = append(aesCiphertexts, AESCiphertextEvidence{
			Ciphertext: append([]byte(nil), evidence.Ciphertext...),
			Source:     evidence.Source,
		})
	}
	return &postProcessingMatcher{
		base:           base,
		rules:          rules,
		contextLines:   cfg.ContextLines,
		aesCiphertexts: aesCiphertexts,
	}
}

func (m *postProcessingMatcher) Match(content []byte) ([]*types.Match, error) {
	return m.MatchWithBlobID(content, types.ComputeBlobID(content))
}

func (m *postProcessingMatcher) MatchWithBlobID(content []byte, blobID types.BlobID) ([]*types.Match, error) {
	matches, err := m.base.MatchWithBlobID(content, blobID)
	if err != nil {
		return nil, err
	}
	rule := m.rules[aesPasswordFlowRuleID]
	if rule == nil {
		return matches, nil
	}
	return expandAESPasswordFlowMatches(content, blobID, rule, matches, m.contextLines, m.aesCiphertexts), nil
}

func (m *postProcessingMatcher) Close() error {
	return m.base.Close()
}

func expandAESPasswordFlowMatches(content []byte, blobID types.BlobID, rule *types.Rule, matches []*types.Match, contextLines int, aesCiphertexts []AESCiphertextEvidence) []*types.Match {
	result := make([]*types.Match, 0, len(matches))
	seen := make(map[string]struct{}, len(matches))
	for _, match := range matches {
		if match.RuleID != aesPasswordFlowRuleID || len(match.NamedGroups["runtime_aes_password"]) > 0 {
			appendUniqueMatch(&result, seen, match)
			continue
		}

		expanded := expandAESPasswordWrapperCalls(content, blobID, rule, match, contextLines, aesCiphertexts)
		if len(expanded) == 0 {
			appendUniqueMatch(&result, seen, match)
			continue
		}
		for _, callMatch := range expanded {
			appendUniqueMatch(&result, seen, callMatch)
		}
	}
	return result
}

func appendUniqueMatch(dst *[]*types.Match, seen map[string]struct{}, match *types.Match) {
	if _, ok := seen[match.StructuralID]; ok {
		return
	}
	seen[match.StructuralID] = struct{}{}
	*dst = append(*dst, match)
}

func expandAESPasswordWrapperCalls(content []byte, blobID types.BlobID, rule *types.Rule, wrapper *types.Match, contextLines int, aesCiphertexts []AESCiphertextEvidence) []*types.Match {
	fn := firstNamedGroup(wrapper, "aes_password_encryptor", "aes_password_encryptor_arrow")
	if fn == "" {
		return nil
	}

	keySource := firstNamedGroup(wrapper, "aes_password_key_source", "aes_password_key_source_arrow")
	staticKey := staticAESKeyFromWrapper(wrapper)
	if staticKey == "" && keySource != "" {
		staticKey = resolveNearestJSStringAssignment(content, int(wrapper.Location.Offset.Start), keySource)
	}

	searchStart := int(wrapper.Location.Offset.Start)
	if searchStart < 0 || searchStart >= len(content) {
		return nil
	}
	calls := findAESPasswordCalls(content[searchStart:], fn)
	var matches []*types.Match
	if evidenceMatch := buildAESPasswordEvidenceMatch(content, blobID, rule, wrapper, contextLines, fn, keySource, staticKey, aesCiphertexts); evidenceMatch != nil {
		matches = append(matches, evidenceMatch)
	}
	for _, call := range calls {
		callStart := call.callStart + searchStart
		callEnd := call.callEnd + searchStart
		argStart := call.argStart + searchStart
		argEnd := call.argEnd + searchStart

		arg := strings.TrimSpace(string(content[argStart:argEnd]))
		passwordValue, literal := parseJSStringLiteral(arg)
		if literal && !hasPasswordContextBeforeCall(content, callStart) {
			continue
		}
		if !literal && !isPasswordInputExpression(arg) {
			continue
		}

		namedGroups := map[string][]byte{
			"aes_key_mode":          []byte("ECB"),
			"aes_key_padding":       []byte("Pkcs7"),
			"encryptor":             []byte(fn),
			"password_input":        []byte(arg),
			"password_value_source": []byte("runtime input; not embedded in scanned content"),
		}
		groups := [][]byte{[]byte(fn), []byte(arg)}
		if keySource != "" {
			namedGroups["aes_key_source"] = []byte(keySource)
		}
		if staticKey != "" && plausibleStaticAESKey(staticKey) {
			namedGroups["aes_key"] = []byte(staticKey)
			groups = append(groups, []byte(staticKey))
		}
		if literal {
			delete(namedGroups, "password_value_source")
			namedGroups["password_value"] = []byte(passwordValue)
			groups = append(groups, []byte(passwordValue))
		}

		matches = append(matches, buildSyntheticMatch(
			content,
			blobID,
			rule,
			callStart,
			callEnd,
			groups,
			namedGroups,
			contextLines,
		))
	}
	return matches
}

type decryptedAESCiphertext struct {
	ciphertext string
	plaintext  string
	source     string
}

func buildAESPasswordEvidenceMatch(content []byte, blobID types.BlobID, rule *types.Rule, wrapper *types.Match, contextLines int, fn, keySource, staticKey string, evidence []AESCiphertextEvidence) *types.Match {
	decrypted := decryptAESPasswordEvidence(staticKey, evidence)
	if len(decrypted) == 0 {
		return nil
	}

	namedGroups := map[string][]byte{
		"aes_key":               []byte(staticKey),
		"aes_key_mode":          []byte("ECB"),
		"aes_key_padding":       []byte("Pkcs7"),
		"aes_validation":        []byte("validated AES-ECB/PKCS7 decryption with printable UTF-8 plaintext"),
		"encryptor":             []byte(fn),
		"evidence_scope":        []byte("shared password encryptor; exact runtime call site not observed"),
		"password_value_source": []byte("owner-supplied ciphertext decrypted with the detected client-side key"),
	}
	if keySource != "" {
		namedGroups["aes_key_source"] = []byte(keySource)
	}
	groups := [][]byte{[]byte(fn), []byte(staticKey)}
	for i, item := range decrypted {
		suffix := ""
		if i > 0 {
			suffix = fmt.Sprintf("_%d", i+1)
		}
		namedGroups["aes_ciphertext"+suffix] = []byte(item.ciphertext)
		namedGroups["aes_ciphertext_source"+suffix] = []byte(item.source)
		namedGroups["password_value"+suffix] = []byte(item.plaintext)
		groups = append(groups, []byte(item.ciphertext), []byte(item.plaintext))
	}

	start := int(wrapper.Location.Offset.Start)
	end := int(wrapper.Location.Offset.End)
	if start < 0 || end <= start || end > len(content) {
		return nil
	}
	return buildSyntheticMatch(content, blobID, rule, start, end, groups, namedGroups, contextLines)
}

func decryptAESPasswordEvidence(key string, evidence []AESCiphertextEvidence) []decryptedAESCiphertext {
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return nil
	}

	seen := make(map[string]struct{})
	decrypted := make([]decryptedAESCiphertext, 0, len(evidence))
	for _, item := range evidence {
		if len(item.Ciphertext) == 0 || len(item.Ciphertext)%block.BlockSize() != 0 {
			continue
		}
		plaintext := make([]byte, len(item.Ciphertext))
		for offset := 0; offset < len(item.Ciphertext); offset += block.BlockSize() {
			block.Decrypt(plaintext[offset:offset+block.BlockSize()], item.Ciphertext[offset:offset+block.BlockSize()])
		}
		plaintext, ok := strictPKCS7Unpad(plaintext, block.BlockSize())
		if !ok || !plausiblePasswordPlaintext(plaintext) {
			continue
		}
		encoded := base64.StdEncoding.EncodeToString(item.Ciphertext)
		key := encoded + "\x00" + string(plaintext)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		source := strings.TrimSpace(item.Source)
		if source == "" {
			source = "owner-supplied evidence"
		}
		decrypted = append(decrypted, decryptedAESCiphertext{
			ciphertext: encoded,
			plaintext:  string(plaintext),
			source:     source,
		})
	}
	return decrypted
}

func strictPKCS7Unpad(value []byte, blockSize int) ([]byte, bool) {
	if len(value) == 0 || blockSize <= 0 || len(value)%blockSize != 0 {
		return nil, false
	}
	padding := int(value[len(value)-1])
	if padding == 0 || padding > blockSize || padding > len(value) {
		return nil, false
	}
	for _, b := range value[len(value)-padding:] {
		if int(b) != padding {
			return nil, false
		}
	}
	return value[:len(value)-padding], true
}

func plausiblePasswordPlaintext(value []byte) bool {
	if len(value) == 0 || len(value) > 512 || !utf8.Valid(value) {
		return false
	}
	for _, r := range string(value) {
		if !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

type aesPasswordCall struct {
	callStart int
	callEnd   int
	argStart  int
	argEnd    int
}

func findAESPasswordCalls(content []byte, fn string) []aesPasswordCall {
	passwordName := `(?i:(?:[A-Za-z_$][\w$]*)?(?:password|passwd)|pwd)`
	memberExpression := `(?:[A-Za-z_$][\w$]*\s*(?:\?\.|\.)\s*){0,7}` + passwordName
	quotedLiteral := `(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')`
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`(?:^|[^\w$])(?P<call>` + regexp.QuoteMeta(fn) + `\s*\(\s*(?P<arg>` + memberExpression + `)\s*\))`),
		regexp.MustCompile(`(?i:(?:[A-Za-z_$][\w$]*)?(?:password|passwd)|pwd)\s*["']?\s*[:=]\s*(?P<call>` + regexp.QuoteMeta(fn) + `\s*\(\s*(?P<arg>` + quotedLiteral + `)\s*\))`),
	}

	var calls []aesPasswordCall
	seen := make(map[[2]int]struct{})
	for _, pattern := range patterns {
		callGroup := pattern.SubexpIndex("call")
		argGroup := pattern.SubexpIndex("arg")
		for _, indexes := range pattern.FindAllSubmatchIndex(content, -1) {
			callStart, callEnd := submatchSpan(indexes, callGroup)
			argStart, argEnd := submatchSpan(indexes, argGroup)
			if callStart < 0 || argStart < 0 {
				continue
			}
			key := [2]int{callStart, callEnd}
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			calls = append(calls, aesPasswordCall{
				callStart: callStart,
				callEnd:   callEnd,
				argStart:  argStart,
				argEnd:    argEnd,
			})
		}
	}
	sort.Slice(calls, func(i, j int) bool { return calls[i].callStart < calls[j].callStart })
	return calls
}

func staticAESKeyFromWrapper(wrapper *types.Match) string {
	for _, name := range []string{"aes_password_static_key_double", "aes_password_static_key_double_arrow"} {
		if value := wrapper.NamedGroups[name]; len(value) > 0 {
			return decodeJSStringContent(string(value), '"')
		}
	}
	for _, name := range []string{"aes_password_static_key_single", "aes_password_static_key_single_arrow"} {
		if value := wrapper.NamedGroups[name]; len(value) > 0 {
			return decodeJSStringContent(string(value), '\'')
		}
	}
	return ""
}

func firstNamedGroup(match *types.Match, names ...string) string {
	for _, name := range names {
		if value := match.NamedGroups[name]; len(value) > 0 {
			return string(value)
		}
	}
	return ""
}

func submatchSpan(indexes []int, group int) (int, int) {
	startIndex := group * 2
	if group < 0 || startIndex+1 >= len(indexes) {
		return -1, -1
	}
	return indexes[startIndex], indexes[startIndex+1]
}

func isPasswordInputExpression(value string) bool {
	value = strings.ReplaceAll(value, " ", "")
	value = strings.ReplaceAll(value, "?.", ".")
	parts := strings.Split(value, ".")
	name := strings.ToLower(parts[len(parts)-1])
	name = strings.ReplaceAll(name, "_", "")
	return name == "password" || name == "passwd" || name == "pwd" ||
		strings.HasSuffix(name, "password") || strings.HasSuffix(name, "passwd")
}

func hasPasswordContextBeforeCall(content []byte, callStart int) bool {
	start := callStart - 128
	if start < 0 {
		start = 0
	}
	prefix := content[start:callStart]
	re := regexp.MustCompile(`(?i)(?:(?:[A-Za-z_$][\w$]*)?(?:password|passwd)|pwd)\s*["']?\s*[:=]\s*$`)
	return re.Match(prefix)
}

func resolveNearestJSStringAssignment(content []byte, before int, variable string) string {
	if before <= 0 || before > len(content) || variable == "" {
		return ""
	}
	start := before - 64*1024
	if start < 0 {
		start = 0
	}
	prefix := content[start:before]
	re := regexp.MustCompile(
		`(?:^|[^\w$])` + regexp.QuoteMeta(variable) +
			`\s*=\s*(?:"(?P<double>(?:\\.|[^"\\])*)"|'(?P<single>(?:\\.|[^'\\])*)')`,
	)
	doubleGroup := re.SubexpIndex("double")
	singleGroup := re.SubexpIndex("single")
	all := re.FindAllSubmatchIndex(prefix, -1)
	if len(all) == 0 {
		return ""
	}
	indexes := all[len(all)-1]
	if begin, end := submatchSpan(indexes, doubleGroup); begin >= 0 {
		return decodeJSStringContent(string(prefix[begin:end]), '"')
	}
	if begin, end := submatchSpan(indexes, singleGroup); begin >= 0 {
		return decodeJSStringContent(string(prefix[begin:end]), '\'')
	}
	return ""
}

func parseJSStringLiteral(value string) (string, bool) {
	if len(value) < 2 || (value[0] != '"' && value[0] != '\'') || value[len(value)-1] != value[0] {
		return "", false
	}
	return decodeJSStringContent(value[1:len(value)-1], rune(value[0])), true
}

func decodeJSStringContent(value string, quote rune) string {
	if quote == '\'' {
		value = strings.ReplaceAll(value, `\'`, `'`)
		value = strings.ReplaceAll(value, `"`, `\"`)
	}
	decoded, err := strconv.Unquote(`"` + value + `"`)
	if err != nil {
		return value
	}
	return decoded
}

func plausibleStaticAESKey(value string) bool {
	switch len([]byte(value)) {
	case 8, 16, 24, 32:
	default:
		return false
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func buildSyntheticMatch(content []byte, blobID types.BlobID, rule *types.Rule, start, end int, groups [][]byte, namedGroups map[string][]byte, contextLines int) *types.Match {
	var before, after []byte
	if contextLines > 0 {
		before, after = ExtractContext(content, start, end, contextLines)
	}
	match := &types.Match{
		BlobID:      blobID,
		RuleID:      rule.ID,
		RuleName:    rule.Name,
		Groups:      groups,
		NamedGroups: namedGroups,
		Location: types.Location{Offset: types.OffsetSpan{
			Start: int64(start),
			End:   int64(end),
		}},
		Snippet: types.Snippet{
			Before:   before,
			Matching: append([]byte(nil), content[start:end]...),
			After:    after,
		},
	}
	match.StructuralID = match.ComputeStructuralID(rule.StructuralID)
	match.FindingID = types.ComputeFindingID(rule.StructuralID, groups)
	return match
}
