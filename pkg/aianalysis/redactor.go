package aianalysis

import (
	"net/url"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
)

var (
	fullURLPattern         = regexp.MustCompile(`https?://[^\s"'<>\\)]+`)
	domainPattern          = regexp.MustCompile(`\b(?:[A-Za-z0-9-]{2,}\.)+[A-Za-z]{2,}\b`)
	authHeaderPattern      = regexp.MustCompile(`(?i)(authorization\s*[:=]\s*["']?)(bearer|basic)\s+[^"',\s]+`)
	cookiePattern          = regexp.MustCompile(`(?i)((?:cookie|set-cookie)\s*[:=]\s*["']?)[^"'\n]+`)
	querySecretPattern     = regexp.MustCompile(`(?i)([?&](?:token|key|secret|password|passwd|auth|session|jwt|access_token|id_token|refresh_token)=)[^&\s"'<>]+`)
	obviousSecretPattern   = regexp.MustCompile(`(?i)((?:api[_-]?key|secret|token|password|passwd|client[_-]?secret|access[_-]?token|refresh[_-]?token)\s*[:=]\s*["']?)[^"',\s]{6,}`)
	highEntropyLikePattern = regexp.MustCompile(`\b[A-Za-z0-9_/\-+=]{32,}\b`)
)

type Redactor struct {
	mode          CloudRedactionMode
	targetHosts   map[string]bool
	mu            sync.Mutex
	originMap     map[string]string
	hostMap       map[string]string
	filePathMap   map[string]string
	secretCounter int
}

type RedactionMap struct {
	CloudRedactionMode CloudRedactionMode `json:"cloud_redaction_mode"`
	TargetHosts        []string           `json:"target_hosts"`
	Origins            map[string]string  `json:"origins"`
	Hosts              map[string]string  `json:"hosts"`
	FilePaths          map[string]string  `json:"file_paths"`
}

func NewRedactor(mode CloudRedactionMode, targetHints []string) *Redactor {
	r := &Redactor{
		mode:        mode,
		targetHosts: make(map[string]bool),
		originMap:   make(map[string]string),
		hostMap:     make(map[string]string),
		filePathMap: make(map[string]string),
	}
	for _, hint := range targetHints {
		host := hostFromHint(hint)
		if host != "" {
			r.targetHosts[strings.ToLower(host)] = true
		}
	}
	return r
}

func (r *Redactor) RedactContent(content string) string {
	content = fullURLPattern.ReplaceAllStringFunc(content, func(value string) string {
		return r.redactURL(value)
	})
	content = domainPattern.ReplaceAllStringFunc(content, func(value string) string {
		return r.placeholderForHost(value)
	})
	content = authHeaderPattern.ReplaceAllString(content, "${1}${2} SECRET_VALUE_REDACTED")
	content = cookiePattern.ReplaceAllString(content, "${1}COOKIE_VALUE_REDACTED")
	content = querySecretPattern.ReplaceAllString(content, "${1}SECRET_VALUE_REDACTED")
	content = obviousSecretPattern.ReplaceAllStringFunc(content, func(value string) string {
		r.mu.Lock()
		r.secretCounter++
		id := r.secretCounter
		r.mu.Unlock()
		parts := obviousSecretPattern.FindStringSubmatch(value)
		if len(parts) > 1 {
			return parts[1] + "SECRET_CANDIDATE_" + intString(id)
		}
		return "SECRET_CANDIDATE_" + intString(id)
	})
	if r.mode == CloudRedactionStandard {
		content = highEntropyLikePattern.ReplaceAllStringFunc(content, func(value string) string {
			if looksLikePlaceholder(value) {
				return value
			}
			return "HIGH_ENTROPY_VALUE_REDACTED_LEN_" + intString(len(value))
		})
	}
	return content
}

func (r *Redactor) RedactPath(path string) string {
	if strings.TrimSpace(path) == "" {
		return ""
	}
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		return r.redactURL(path)
	}
	clean := filepath.ToSlash(path)
	base := filepath.Base(clean)
	if base == "." || base == "/" || base == "" {
		base = "file"
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if existing, ok := r.filePathMap[clean]; ok {
		return existing
	}
	placeholder := "FILE_" + intString(len(r.filePathMap)+1) + "_" + sanitizeCloudPathSegment(base)
	r.filePathMap[clean] = placeholder
	return placeholder
}

func (r *Redactor) Snapshot() RedactionMap {
	r.mu.Lock()
	defer r.mu.Unlock()
	targetHosts := make([]string, 0, len(r.targetHosts))
	for host := range r.targetHosts {
		targetHosts = append(targetHosts, host)
	}
	sort.Strings(targetHosts)
	return RedactionMap{
		CloudRedactionMode: r.mode,
		TargetHosts:        targetHosts,
		Origins:            copyStringMap(r.originMap),
		Hosts:              copyStringMap(r.hostMap),
		FilePaths:          copyStringMap(r.filePathMap),
	}
}

func (r *Redactor) redactURL(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" {
		return raw
	}
	origin := parsed.Scheme + "://" + parsed.Host
	placeholder := r.placeholderForOrigin(origin, parsed.Hostname())
	parsed.Scheme = ""
	parsed.Host = ""
	redacted := placeholder + parsed.String()
	if r.mode == CloudRedactionStandard && parsed.RawQuery != "" {
		redacted = querySecretPattern.ReplaceAllString(redacted, "${1}SECRET_VALUE_REDACTED")
	}
	return redacted
}

func (r *Redactor) placeholderForOrigin(origin, host string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if existing, ok := r.originMap[origin]; ok {
		return existing
	}
	prefix := "EXTERNAL_ORIGIN_"
	if r.targetHosts[strings.ToLower(host)] {
		prefix = "TARGET_ORIGIN_"
	}
	placeholder := prefix + intString(countPrefixValues(r.originMap, prefix)+1)
	r.originMap[origin] = placeholder
	return placeholder
}

func (r *Redactor) placeholderForHost(host string) string {
	host = strings.ToLower(strings.Trim(host, "."))
	if host == "" {
		return host
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if existing, ok := r.hostMap[host]; ok {
		return existing
	}
	prefix := "EXTERNAL_HOST_"
	if r.targetHosts[host] {
		prefix = "TARGET_HOST_"
	}
	placeholder := prefix + intString(countPrefixValues(r.hostMap, prefix)+1)
	r.hostMap[host] = placeholder
	return placeholder
}

func hostFromHint(hint string) string {
	hint = strings.TrimSpace(hint)
	if hint == "" {
		return ""
	}
	if strings.HasPrefix(hint, "http://") || strings.HasPrefix(hint, "https://") {
		parsed, err := url.Parse(hint)
		if err == nil {
			return parsed.Hostname()
		}
	}
	if strings.Contains(hint, "://") {
		return ""
	}
	if strings.Contains(hint, "/") {
		return ""
	}
	return strings.Trim(hint, ".")
}

func looksLikePlaceholder(value string) bool {
	return strings.HasPrefix(value, "TARGET_") ||
		strings.HasPrefix(value, "EXTERNAL_") ||
		strings.HasPrefix(value, "SECRET_") ||
		strings.HasPrefix(value, "HIGH_ENTROPY_")
}

func copyStringMap(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func countPrefixValues(values map[string]string, prefix string) int {
	count := 0
	for _, value := range values {
		if strings.HasPrefix(value, prefix) {
			count++
		}
	}
	return count
}

func sanitizeCloudPathSegment(value string) string {
	var b strings.Builder
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '-' || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	out := strings.Trim(b.String(), "._-")
	if out == "" {
		return "file"
	}
	return out
}
