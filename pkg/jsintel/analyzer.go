package jsintel

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
)

type Category string

const (
	CategoryEndpoint               Category = "endpoint"
	CategoryCloudURL               Category = "cloud_url"
	CategorySubdomain              Category = "subdomain"
	CategoryDependency             Category = "dependency"
	CategoryDependencyConfusion    Category = "dependency_confusion"
	CategorySourceMap              Category = "source_map"
	CategoryGenericSecretHeuristic Category = "generic_secret_heuristic"
)

type Config struct {
	Endpoints      bool
	CloudURLs      bool
	Subdomains     bool
	Dependencies   bool
	SourceMaps     bool
	GenericSecrets bool
	NPMCheck       bool
	NPMRegistryURL string
	HTTPClient     *http.Client
}

func DefaultConfig() Config {
	return Config{
		Endpoints:      true,
		CloudURLs:      true,
		Subdomains:     true,
		Dependencies:   true,
		SourceMaps:     true,
		GenericSecrets: false,
		NPMRegistryURL: "https://registry.npmjs.org",
	}
}

type Analyzer struct {
	cfg        Config
	httpClient *http.Client
}

type Result struct {
	Findings []Finding
	Sources  []SourceFile
	Warnings []string
}

type Finding struct {
	Category   Category `json:"category"`
	Value      string   `json:"value"`
	Detail     string   `json:"detail,omitempty"`
	Method     string   `json:"method,omitempty"`
	Confidence string   `json:"confidence"`
	Line       int      `json:"line,omitempty"`
	Column     int      `json:"column,omitempty"`
	Active     bool     `json:"active,omitempty"`
}

type SourceFile struct {
	Path      string
	Content   []byte
	SourceMap string
}

func New(cfg Config) *Analyzer {
	if cfg.NPMRegistryURL == "" {
		cfg.NPMRegistryURL = "https://registry.npmjs.org"
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	return &Analyzer{cfg: cfg, httpClient: client}
}

func (a *Analyzer) Analyze(content []byte, source string) Result {
	text := string(content)
	var result Result
	seen := make(map[string]struct{})
	add := func(f Finding) {
		if f.Confidence == "" {
			f.Confidence = "info"
		}
		key := string(f.Category) + "\x00" + f.Method + "\x00" + f.Value + "\x00" + f.Detail
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		result.Findings = append(result.Findings, f)
	}

	if a.cfg.Endpoints {
		for _, f := range extractEndpoints(text) {
			add(f)
		}
	}
	if a.cfg.CloudURLs {
		for _, f := range extractCloudURLs(text) {
			add(f)
		}
	}
	if a.cfg.Subdomains {
		for _, f := range extractSubdomains(text) {
			add(f)
		}
	}
	var deps []dependencyHit
	if a.cfg.Dependencies || a.cfg.NPMCheck {
		deps = extractDependencies(content)
		for _, dep := range deps {
			if a.cfg.Dependencies {
				add(Finding{
					Category:   CategoryDependency,
					Value:      dep.Name,
					Detail:     dep.Source,
					Confidence: "info",
					Line:       dep.Line,
					Column:     dep.Column,
				})
			}
		}
	}
	if a.cfg.SourceMaps {
		sourceFindings, sources, warnings := extractSourceMaps(text, source)
		for _, f := range sourceFindings {
			add(f)
		}
		result.Sources = append(result.Sources, sources...)
		result.Warnings = append(result.Warnings, warnings...)
	}
	if a.cfg.GenericSecrets {
		for _, f := range extractGenericSecrets(text) {
			add(f)
		}
	}
	if a.cfg.NPMCheck {
		npmFindings, npmWarnings := a.checkNPMDependencies(deps)
		for _, f := range npmFindings {
			add(f)
		}
		result.Warnings = append(result.Warnings, npmWarnings...)
	}

	return result
}

func DisplayValue(f Finding) string {
	if f.Category == CategoryGenericSecretHeuristic {
		return f.Value
	}
	return redactSensitiveURLParts(f.Value)
}

func SortFindings(findings []Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].Category != findings[j].Category {
			return findings[i].Category < findings[j].Category
		}
		if findings[i].Line != findings[j].Line {
			return findings[i].Line < findings[j].Line
		}
		return findings[i].Value < findings[j].Value
	})
}

var (
	endpointCallRe  = regexp.MustCompile("(?i)\\.\\s*(get|post|put|delete|patch)\\s*\\(\\s*['\"`]([^'\"`]+)['\"`]")
	fetchCallRe     = regexp.MustCompile("(?i)\\b(fetch|importScripts)\\s*\\(\\s*['\"`]([^'\"`]+)['\"`]")
	urlPropertyRe   = regexp.MustCompile("(?i)\\b(?:url|uri|endpoint|path)\\s*[:=]\\s*['\"`]([^'\"`]+)['\"`]")
	cloudURLRe      = regexp.MustCompile(`(?i)\b(?:[a-z0-9][a-z0-9.-]*\.s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com(?:/[A-Za-z0-9._~!$&'()*+,;=:@%/-]*)?|s3[.-][a-z0-9-]+\.amazonaws\.com/[A-Za-z0-9._~!$&'()*+,;=:@%/-]+|storage\.googleapis\.com/[A-Za-z0-9._~!$&'()*+,;=:@%/-]+|[a-z0-9][a-z0-9.-]*\.blob\.core\.windows\.net/[A-Za-z0-9._~!$&'()*+,;=:@%/-]+|[a-z0-9][a-z0-9.-]*\.digitaloceanspaces\.com/[A-Za-z0-9._~!$&'()*+,;=:@%/-]*)\b`)
	subdomainRe     = regexp.MustCompile(`(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b`)
	nodeModulesRe   = regexp.MustCompile(`(?i)(?:^|[/\\"'])node_modules/(@[a-z0-9._-]+/[a-z0-9._-]+|[a-z0-9._-]+)`)
	requireRe       = regexp.MustCompile("(?i)\\b(?:require|import)\\s*\\(\\s*['\"`]([^'\"`]+)['\"`]\\s*\\)")
	importFromRe    = regexp.MustCompile("(?i)\\bfrom\\s+['\"`]([^'\"`]+)['\"`]")
	sourceMapURLRe  = regexp.MustCompile(`(?m)(?://[#@]|/\*[#@])\s*sourceMappingURL=([^\s*]+)`)
	genericSecretRe = regexp.MustCompile(
		"(?i)\\b([a-z0-9_.-]*(?:api[_-]?key|secret|token|password|passwd|bearer|authorization|aws_access_key_id|aws_secret_access_key)[a-z0-9_.-]*)\\b\\s*[:=]\\s*['\"`]([^'\"`\\s]{8,})['\"`]",
	)
)

func extractEndpoints(text string) []Finding {
	var findings []Finding
	for _, match := range endpointCallRe.FindAllStringSubmatchIndex(text, -1) {
		method := strings.ToUpper(text[match[2]:match[3]])
		value := text[match[4]:match[5]]
		if !isEndpointValue(value) {
			continue
		}
		line, col := lineColumn(text, match[4])
		findings = append(findings, Finding{
			Category:   CategoryEndpoint,
			Method:     method,
			Value:      value,
			Detail:     "method call",
			Confidence: "info",
			Line:       line,
			Column:     col,
		})
	}
	for _, match := range fetchCallRe.FindAllStringSubmatchIndex(text, -1) {
		value := text[match[4]:match[5]]
		if !isEndpointValue(value) {
			continue
		}
		line, col := lineColumn(text, match[4])
		findings = append(findings, Finding{
			Category:   CategoryEndpoint,
			Value:      value,
			Detail:     strings.ToLower(text[match[2]:match[3]]) + " call",
			Confidence: "info",
			Line:       line,
			Column:     col,
		})
	}
	for _, match := range urlPropertyRe.FindAllStringSubmatchIndex(text, -1) {
		value := text[match[2]:match[3]]
		if !isEndpointValue(value) {
			continue
		}
		line, col := lineColumn(text, match[2])
		findings = append(findings, Finding{
			Category:   CategoryEndpoint,
			Value:      value,
			Detail:     "url-like property",
			Confidence: "info",
			Line:       line,
			Column:     col,
		})
	}
	return findings
}

func isEndpointValue(value string) bool {
	if len(value) < 2 || len(value) > 300 {
		return false
	}
	lower := strings.ToLower(value)
	if strings.HasPrefix(lower, "data:") || strings.HasPrefix(lower, "javascript:") {
		return false
	}
	if strings.ContainsAny(value, "<>{}") {
		return false
	}
	return strings.Contains(value, "/") || strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://")
}

func extractCloudURLs(text string) []Finding {
	var findings []Finding
	for _, match := range cloudURLRe.FindAllStringIndex(text, -1) {
		value := trimTrailingPunctuation(text[match[0]:match[1]])
		line, col := lineColumn(text, match[0])
		findings = append(findings, Finding{
			Category:   CategoryCloudURL,
			Value:      value,
			Confidence: "info",
			Line:       line,
			Column:     col,
		})
	}
	return findings
}

func extractSubdomains(text string) []Finding {
	var findings []Finding
	for _, match := range subdomainRe.FindAllStringIndex(text, -1) {
		value := strings.ToLower(trimTrailingPunctuation(text[match[0]:match[1]]))
		if isNoisyDomain(value) {
			continue
		}
		line, col := lineColumn(text, match[0])
		findings = append(findings, Finding{
			Category:   CategorySubdomain,
			Value:      value,
			Confidence: "info",
			Line:       line,
			Column:     col,
		})
	}
	return findings
}

func isNoisyDomain(value string) bool {
	if strings.Contains(value, "..") || strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") {
		return true
	}
	if strings.HasSuffix(value, ".js") || strings.HasSuffix(value, ".json") || strings.HasSuffix(value, ".css") {
		return true
	}
	parts := strings.Split(value, ".")
	if len(parts) < 2 {
		return true
	}
	allNumeric := true
	for _, part := range parts {
		for _, r := range part {
			if !unicode.IsDigit(r) {
				allNumeric = false
				break
			}
		}
	}
	return allNumeric
}

type dependencyHit struct {
	Name   string
	Source string
	Line   int
	Column int
}

func extractDependencies(content []byte) []dependencyHit {
	text := string(content)
	seen := make(map[string]dependencyHit)
	add := func(name, source string, offset int) {
		name = normalizePackageName(name)
		if !isPackageName(name) {
			return
		}
		line, col := lineColumn(text, offset)
		if existing, ok := seen[name]; ok {
			if existing.Line <= line {
				return
			}
		}
		seen[name] = dependencyHit{Name: name, Source: source, Line: line, Column: col}
	}

	extractDependenciesFromJSON(content, add)

	for _, match := range nodeModulesRe.FindAllStringSubmatchIndex(text, -1) {
		add(text[match[2]:match[3]], "node_modules path", match[2])
	}
	for _, match := range requireRe.FindAllStringSubmatchIndex(text, -1) {
		add(text[match[2]:match[3]], "import/require", match[2])
	}
	for _, match := range importFromRe.FindAllStringSubmatchIndex(text, -1) {
		add(text[match[2]:match[3]], "import/from", match[2])
	}

	deps := make([]dependencyHit, 0, len(seen))
	for _, dep := range seen {
		deps = append(deps, dep)
	}
	sort.SliceStable(deps, func(i, j int) bool {
		if deps[i].Line != deps[j].Line {
			return deps[i].Line < deps[j].Line
		}
		return deps[i].Name < deps[j].Name
	})
	return deps
}

func extractDependenciesFromJSON(content []byte, add func(name, source string, offset int)) {
	var root map[string]any
	if err := json.Unmarshal(content, &root); err != nil {
		return
	}
	for _, section := range []string{"dependencies", "devDependencies", "peerDependencies", "optionalDependencies"} {
		obj, ok := root[section].(map[string]any)
		if !ok {
			continue
		}
		for name := range obj {
			add(name, section, strings.Index(string(content), `"`+name+`"`)+1)
		}
	}
	packages, ok := root["packages"].(map[string]any)
	if !ok {
		return
	}
	for path := range packages {
		const prefix = "node_modules/"
		if strings.Contains(path, prefix) {
			add(path[strings.LastIndex(path, prefix)+len(prefix):], "package-lock packages", strings.Index(string(content), path))
		}
	}
}

func normalizePackageName(name string) string {
	name = strings.TrimSpace(name)
	name = strings.Trim(name, `"'`)
	if strings.HasPrefix(name, "node:") {
		return ""
	}
	if strings.HasPrefix(name, ".") || strings.HasPrefix(name, "/") {
		return ""
	}
	if strings.HasPrefix(name, "@") {
		parts := strings.Split(name, "/")
		if len(parts) >= 2 {
			return strings.ToLower(parts[0] + "/" + parts[1])
		}
		return ""
	}
	parts := strings.Split(name, "/")
	if len(parts) == 0 {
		return ""
	}
	return strings.ToLower(parts[0])
}

func isPackageName(name string) bool {
	if name == "" || len(name) > 214 {
		return false
	}
	if strings.Contains(name, "..") || strings.ContainsAny(name, `\ :;"'`) {
		return false
	}
	if strings.HasPrefix(name, "@") {
		parts := strings.Split(name, "/")
		return len(parts) == 2 && validPackageSegment(parts[0][1:]) && validPackageSegment(parts[1])
	}
	return validPackageSegment(name)
}

func validPackageSegment(segment string) bool {
	if segment == "" {
		return false
	}
	for _, r := range segment {
		if unicode.IsLower(r) || unicode.IsDigit(r) || r == '-' || r == '_' || r == '.' {
			continue
		}
		return false
	}
	return true
}

type sourceMap struct {
	Version        int      `json:"version"`
	Sources        []string `json:"sources"`
	SourcesContent []string `json:"sourcesContent"`
}

func extractSourceMaps(text, source string) ([]Finding, []SourceFile, []string) {
	var findings []Finding
	var sources []SourceFile
	var warnings []string

	for _, match := range sourceMapURLRe.FindAllStringSubmatchIndex(text, -1) {
		ref := strings.TrimSpace(text[match[2]:match[3]])
		ref = strings.TrimSuffix(ref, "*/")
		line, col := lineColumn(text, match[2])
		if !strings.HasPrefix(ref, "data:") {
			findings = append(findings, Finding{
				Category:   CategorySourceMap,
				Value:      ref,
				Detail:     "external source map reference",
				Confidence: "info",
				Line:       line,
				Column:     col,
			})
			continue
		}

		sm, err := decodeInlineSourceMap(ref)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("source map decode failed for %s: %v", source, err))
			continue
		}
		embedded := 0
		for i, content := range sm.SourcesContent {
			if content == "" {
				continue
			}
			path := fmt.Sprintf("source-%d.js", i+1)
			if i < len(sm.Sources) && strings.TrimSpace(sm.Sources[i]) != "" {
				path = sanitizeSourcePath(sm.Sources[i])
			}
			sources = append(sources, SourceFile{
				Path:      path,
				Content:   []byte(content),
				SourceMap: ref,
			})
			embedded++
		}
		findings = append(findings, Finding{
			Category:   CategorySourceMap,
			Value:      "inline source map",
			Detail:     fmt.Sprintf("%d embedded source file(s)", embedded),
			Confidence: "info",
			Line:       line,
			Column:     col,
		})
	}

	return findings, sources, warnings
}

func decodeInlineSourceMap(ref string) (sourceMap, error) {
	var sm sourceMap
	comma := strings.Index(ref, ",")
	if comma < 0 {
		return sm, fmt.Errorf("data URL has no payload")
	}
	meta := strings.ToLower(ref[:comma])
	payload := ref[comma+1:]
	var data []byte
	var err error
	if strings.Contains(meta, ";base64") {
		data, err = base64.StdEncoding.DecodeString(payload)
		if err != nil {
			return sm, err
		}
	} else {
		decoded, err := url.PathUnescape(payload)
		if err != nil {
			return sm, err
		}
		data = []byte(decoded)
	}
	if err := json.Unmarshal(data, &sm); err != nil {
		return sm, err
	}
	return sm, nil
}

func sanitizeSourcePath(path string) string {
	path = strings.TrimSpace(path)
	path = strings.TrimPrefix(path, "webpack://")
	path = strings.TrimPrefix(path, "./")
	path = strings.ReplaceAll(path, "\\", "/")
	path = strings.ReplaceAll(path, "\x00", "")
	for strings.Contains(path, "../") {
		path = strings.ReplaceAll(path, "../", "")
	}
	if path == "" {
		return "source.js"
	}
	return path
}

func extractGenericSecrets(text string) []Finding {
	var findings []Finding
	for _, match := range genericSecretRe.FindAllStringSubmatchIndex(text, -1) {
		name := text[match[2]:match[3]]
		value := text[match[4]:match[5]]
		if isGenericSecretFalsePositive(value) {
			continue
		}
		confidence := "low"
		if shannonEntropy(value) >= 3.5 {
			confidence = "medium"
		}
		line, col := lineColumn(text, match[4])
		findings = append(findings, Finding{
			Category:   CategoryGenericSecretHeuristic,
			Value:      maskValue(value),
			Detail:     name,
			Confidence: confidence,
			Line:       line,
			Column:     col,
		})
	}
	return findings
}

func isGenericSecretFalsePositive(value string) bool {
	lower := strings.ToLower(value)
	if len(value) < 8 {
		return true
	}
	blocklist := []string{
		"authorization", "bearer", "basic", "token", "secret", "password", "passwd",
		"undefined", "null", "false", "true", "example", "changeme", "placeholder",
	}
	for _, item := range blocklist {
		if lower == item || strings.Contains(lower, item+" value") {
			return true
		}
	}
	return false
}

func (a *Analyzer) checkNPMDependencies(deps []dependencyHit) ([]Finding, []string) {
	var findings []Finding
	var warnings []string
	for _, dep := range deps {
		missing, err := a.packageMissing(dep.Name)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("npm registry check failed for %s: %v", dep.Name, err))
			continue
		}
		if missing {
			findings = append(findings, Finding{
				Category:   CategoryDependencyConfusion,
				Value:      dep.Name,
				Detail:     "package missing from configured npm registry",
				Confidence: "low",
				Line:       dep.Line,
				Column:     dep.Column,
				Active:     true,
			})
		}
	}
	return findings, warnings
}

func (a *Analyzer) packageMissing(name string) (bool, error) {
	base := strings.TrimRight(a.cfg.NPMRegistryURL, "/")
	req, err := http.NewRequest(http.MethodGet, base+"/"+url.PathEscape(name), nil)
	if err != nil {
		return false, err
	}
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return true, nil
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return false, nil
	}
	return false, fmt.Errorf("HTTP %d", resp.StatusCode)
}

func lineColumn(text string, offset int) (int, int) {
	if offset < 0 {
		return 0, 0
	}
	line, col := 1, 1
	for i, r := range text {
		if i >= offset {
			break
		}
		if r == '\n' {
			line++
			col = 1
			continue
		}
		col++
	}
	return line, col
}

func trimTrailingPunctuation(value string) string {
	return strings.TrimRight(value, `.,;:)]}"'`)
}

func shannonEntropy(value string) float64 {
	if value == "" {
		return 0
	}
	counts := make(map[rune]float64)
	for _, r := range value {
		counts[r]++
	}
	length := float64(len([]rune(value)))
	var entropy float64
	for _, count := range counts {
		p := count / length
		entropy -= p * math.Log2(p)
	}
	return entropy
}

func maskValue(value string) string {
	if len(value) <= 8 {
		return "****"
	}
	if len(value) <= 16 {
		return value[:2] + "..." + value[len(value)-2:]
	}
	return value[:4] + "..." + value[len(value)-4:]
}

func redactSensitiveURLParts(value string) string {
	if value == "" || !strings.Contains(value, "?") {
		return value
	}
	parts := strings.SplitN(value, "?", 2)
	query := parts[1]
	fragment := ""
	if idx := strings.Index(query, "#"); idx >= 0 {
		fragment = query[idx:]
		query = query[:idx]
	}
	pairs := strings.Split(query, "&")
	for i, pair := range pairs {
		key, val, found := strings.Cut(pair, "=")
		if !found {
			continue
		}
		if isSensitiveParam(key) && val != "" {
			pairs[i] = key + "=<redacted>"
		}
	}
	return parts[0] + "?" + strings.Join(pairs, "&") + fragment
}

func isSensitiveParam(key string) bool {
	lower := strings.ToLower(key)
	for _, marker := range []string{"token", "secret", "password", "passwd", "key", "auth", "session", "jwt"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}
