package enum

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/dinosn/leaklens/pkg/types"
	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/proto"
)

const (
	defaultBrowserCaptureTimeout = 20 * time.Second
	defaultBrowserCaptureSettle  = 3 * time.Second
	maxBrowserCaptureBodies      = 128
	maxBrowserCaptureEvents      = 256
	runtimeConsolePrefix         = "__leaklens_runtime_crypto__:"
)

type browserCaptureResult struct {
	URLs  []string
	Blobs []browserCaptureBlob
}

type browserCaptureBlob struct {
	Content    []byte
	Provenance types.Provenance
}

type browserResponseMeta struct {
	URL         string
	MimeType    string
	ContentType string
	Status      int
	Resource    string
}

type browserRuntimeEvent struct {
	Seq         int                    `json:"seq"`
	Kind        string                 `json:"kind"`
	Method      string                 `json:"method"`
	Mode        string                 `json:"mode"`
	Padding     string                 `json:"padding"`
	Data        browserRuntimeValue    `json:"data"`
	Key         browserRuntimeValue    `json:"key"`
	Result      browserRuntimeValue    `json:"result"`
	Value       browserRuntimeValue    `json:"value"`
	Algorithm   map[string]interface{} `json:"algorithm"`
	Extractable bool                   `json:"extractable"`
	Usages      []string               `json:"usages"`
}

type browserRuntimeValue struct {
	Type     string `json:"type"`
	Value    string `json:"value"`
	SigBytes int    `json:"sigBytes"`
	Length   int    `json:"length"`
}

type browserLaunchHandle struct {
	ControlURL string
	Cleanup    func()
	Kill       func()
}

var runBrowserRuntimeCapture = defaultRunBrowserRuntimeCapture

func defaultRunBrowserRuntimeCapture(ctx context.Context, e *CrawlEnumerator) (browserCaptureResult, error) {
	captureCtx, cancel := context.WithTimeout(ctx, browserCaptureTimeout(e.Timeout))
	defer cancel()

	handle, err := browserControlURL(captureCtx, e)
	if err != nil {
		return browserCaptureResult{}, err
	}
	connected := false
	defer func() {
		if !connected {
			handle.Kill()
		}
		handle.Cleanup()
	}()

	browser := rod.New().Context(captureCtx).ControlURL(handle.ControlURL).NoDefaultDevice()
	if err := browser.Connect(); err != nil {
		return browserCaptureResult{}, fmt.Errorf("connecting browser: %w", err)
	}
	connected = true
	defer browser.Close()
	_ = (proto.SecuritySetIgnoreCertificateErrors{Ignore: true}).Call(browser)

	page, err := browser.Page(proto.TargetCreateTarget{URL: "about:blank"})
	if err != nil {
		return browserCaptureResult{}, fmt.Errorf("opening browser page: %w", err)
	}
	defer page.Close()
	page = page.Context(captureCtx)

	if err := (proto.NetworkEnable{}).Call(page); err != nil {
		return browserCaptureResult{}, fmt.Errorf("enabling browser network capture: %w", err)
	}
	if err := (proto.RuntimeEnable{}).Call(page); err != nil {
		return browserCaptureResult{}, fmt.Errorf("enabling browser runtime capture: %w", err)
	}
	if _, err := page.EvalOnNewDocument(browserRuntimeHookScript()); err != nil {
		return browserCaptureResult{}, fmt.Errorf("installing browser runtime hooks: %w", err)
	}

	var mu sync.Mutex
	requestURLs := make(map[string]struct{})
	responses := make(map[proto.NetworkRequestID]browserResponseMeta)
	var finished []proto.NetworkRequestID
	var events []browserRuntimeEvent

	eventPage, stopEvents := page.WithCancel()
	go eventPage.EachEvent(
		func(e *proto.NetworkRequestWillBeSent) {
			if e == nil || e.Request == nil || e.Request.URL == "" {
				return
			}
			mu.Lock()
			requestURLs[e.Request.URL] = struct{}{}
			mu.Unlock()
		},
		func(e *proto.NetworkResponseReceived) {
			if e == nil || e.Response == nil || e.Response.URL == "" {
				return
			}
			mu.Lock()
			responses[e.RequestID] = browserResponseMeta{
				URL:      e.Response.URL,
				MimeType: e.Response.MIMEType,
				Status:   int(e.Response.Status),
				Resource: string(e.Type),
			}
			if value := browserHeaderValue(e.Response.Headers, "content-type"); value != "" {
				meta := responses[e.RequestID]
				meta.ContentType = value
				responses[e.RequestID] = meta
			}
			mu.Unlock()
		},
		func(e *proto.NetworkLoadingFinished) {
			if e == nil {
				return
			}
			mu.Lock()
			if len(finished) < maxBrowserCaptureBodies {
				finished = append(finished, e.RequestID)
			}
			mu.Unlock()
		},
		func(e *proto.RuntimeConsoleAPICalled) {
			if e == nil {
				return
			}
			for _, arg := range e.Args {
				if arg == nil || arg.Type != proto.RuntimeRemoteObjectTypeString {
					continue
				}
				raw := arg.Value.Str()
				if !strings.HasPrefix(raw, runtimeConsolePrefix) {
					continue
				}
				var event browserRuntimeEvent
				if err := json.Unmarshal([]byte(strings.TrimPrefix(raw, runtimeConsolePrefix)), &event); err != nil {
					continue
				}
				mu.Lock()
				if len(events) < maxBrowserCaptureEvents {
					events = append(events, event)
				}
				mu.Unlock()
			}
		},
	)()

	if err := page.Navigate(e.TargetURL); err != nil {
		stopEvents()
		return browserCaptureResult{}, fmt.Errorf("navigating browser page: %w", err)
	}
	_ = page.WaitLoad()
	waitForBrowserCaptureSettle(captureCtx)
	stopEvents()

	mu.Lock()
	urlSnapshot := make([]string, 0, len(requestURLs))
	for rawURL := range requestURLs {
		urlSnapshot = append(urlSnapshot, rawURL)
	}
	responseSnapshot := make(map[proto.NetworkRequestID]browserResponseMeta, len(responses))
	for id, meta := range responses {
		responseSnapshot[id] = meta
	}
	finishedSnapshot := append([]proto.NetworkRequestID(nil), finished...)
	eventSnapshot := append([]browserRuntimeEvent(nil), events...)
	mu.Unlock()

	result := browserCaptureResult{URLs: uniqueStrings(urlSnapshot)}
	result.Blobs = append(result.Blobs, browserResponseBlobs(page, responseSnapshot, finishedSnapshot, e.MaxSize)...)
	if storageBlob := browserStorageBlob(page, e.TargetURL); len(storageBlob.Content) > 0 {
		result.Blobs = append(result.Blobs, storageBlob)
	}
	result.Blobs = append(result.Blobs, browserRuntimeCryptoBlobs(e.TargetURL, eventSnapshot)...)
	return result, nil
}

func browserControlURL(ctx context.Context, e *CrawlEnumerator) (browserLaunchHandle, error) {
	if e.ChromeWSURL != "" {
		return browserLaunchHandle{
			ControlURL: e.ChromeWSURL,
			Cleanup:    func() {},
			Kill:       func() {},
		}, nil
	}

	bin := strings.TrimSpace(e.SystemChromePath)
	if bin == "" {
		var ok bool
		bin, ok = launcher.LookPath()
		if !ok {
			return browserLaunchHandle{}, fmt.Errorf("no installed Chrome or Chromium executable found")
		}
	}

	l := launcher.New().
		Context(ctx).
		Bin(bin).
		Headless(true).
		Set("disable-gpu").
		Set("mute-audio").
		Set("ignore-certificate-errors").
		Set("disable-background-networking").
		Set("disable-sync")

	if e.ChromeDataDir != "" {
		l = l.UserDataDir(e.ChromeDataDir)
	}
	if shouldUseHeadlessNoSandboxForEUID(e.NoSandbox, true, "", currentEUID()) {
		l = l.NoSandbox(true)
	}

	controlURL, err := l.Launch()
	if err != nil {
		return browserLaunchHandle{}, fmt.Errorf("launching browser: %w", err)
	}
	return browserLaunchHandle{
		ControlURL: controlURL,
		Cleanup:    l.Cleanup,
		Kill:       l.Kill,
	}, nil
}

func browserCaptureTimeout(crawlTimeout time.Duration) time.Duration {
	timeout := defaultBrowserCaptureTimeout
	if crawlTimeout > 0 && crawlTimeout < timeout {
		timeout = crawlTimeout
	}
	return timeout
}

func waitForBrowserCaptureSettle(ctx context.Context) {
	timer := time.NewTimer(defaultBrowserCaptureSettle)
	defer timer.Stop()
	select {
	case <-ctx.Done():
	case <-timer.C:
	}
}

func browserResponseBlobs(page *rod.Page, responses map[proto.NetworkRequestID]browserResponseMeta, finished []proto.NetworkRequestID, maxSize int64) []browserCaptureBlob {
	if maxSize <= 0 {
		maxSize = 20 * 1024 * 1024
	}
	seen := make(map[proto.NetworkRequestID]struct{}, len(finished))
	var blobs []browserCaptureBlob
	for _, requestID := range finished {
		if _, ok := seen[requestID]; ok {
			continue
		}
		seen[requestID] = struct{}{}
		meta, ok := responses[requestID]
		if !ok || !shouldCaptureBrowserResponse(meta) {
			continue
		}
		body, err := proto.NetworkGetResponseBody{RequestID: requestID}.Call(page)
		if err != nil || body == nil {
			continue
		}
		content := []byte(body.Body)
		if body.Base64Encoded {
			decoded, err := base64.StdEncoding.DecodeString(body.Body)
			if err != nil {
				continue
			}
			content = decoded
		}
		if len(content) == 0 || int64(len(content)) > maxSize || isBinary(content) {
			continue
		}
		blobs = append(blobs, browserCaptureBlob{
			Content: content,
			Provenance: types.ExtendedProvenance{Payload: map[string]interface{}{
				"kind": "browser_response",
				"path": meta.URL + "#browser-response",
				"url":  meta.URL,
			}},
		})
	}
	return blobs
}

func shouldCaptureBrowserResponse(meta browserResponseMeta) bool {
	if meta.Status < 200 || meta.Status >= 300 {
		return false
	}
	contentType := strings.ToLower(meta.ContentType + " " + meta.MimeType)
	switch {
	case strings.Contains(contentType, "javascript"),
		strings.Contains(contentType, "json"),
		strings.Contains(contentType, "source-map"),
		strings.Contains(contentType, "text/plain"),
		strings.Contains(contentType, "text/html"),
		strings.Contains(contentType, "xml"):
		return true
	}
	switch strings.ToLower(meta.Resource) {
	case "document", "script", "xhr", "fetch":
		return true
	default:
		return false
	}
}

func browserHeaderValue(headers proto.NetworkHeaders, name string) string {
	for key, value := range headers {
		if strings.EqualFold(key, name) {
			return value.Str()
		}
	}
	return ""
}

func browserStorageBlob(page *rod.Page, targetURL string) browserCaptureBlob {
	res, err := page.Evaluate(rod.Eval(`() => {
  const readStore = (store) => {
    const out = {};
    if (!store) return out;
    for (let i = 0; i < store.length; i++) {
      const key = store.key(i);
      out[key] = store.getItem(key);
    }
    return out;
  };
  return JSON.stringify({
    localStorage: readStore(window.localStorage),
    sessionStorage: readStore(window.sessionStorage)
  });
}`))
	if err != nil || res == nil || res.Value.Str() == "" {
		return browserCaptureBlob{}
	}
	content := []byte("leaklens_browser_runtime_storage = " + res.Value.Str() + "\n")
	if !storageBlobHasValues(content) {
		return browserCaptureBlob{}
	}
	return browserCaptureBlob{
		Content: content,
		Provenance: types.ExtendedProvenance{Payload: map[string]interface{}{
			"kind": "browser_storage",
			"path": runtimeObservationPath(targetURL, "storage", 0),
		}},
	}
}

func storageBlobHasValues(content []byte) bool {
	var parsed struct {
		LocalStorage   map[string]string `json:"localStorage"`
		SessionStorage map[string]string `json:"sessionStorage"`
	}
	prefix := []byte("leaklens_browser_runtime_storage = ")
	body := strings.TrimSpace(strings.TrimPrefix(string(content), string(prefix)))
	if err := json.Unmarshal([]byte(body), &parsed); err != nil {
		return true
	}
	return len(parsed.LocalStorage) > 0 || len(parsed.SessionStorage) > 0
}

func browserRuntimeCryptoBlobs(targetURL string, events []browserRuntimeEvent) []browserCaptureBlob {
	sort.SliceStable(events, func(i, j int) bool {
		return events[i].Seq < events[j].Seq
	})

	var blobs []browserCaptureBlob
	recentUtf8 := make([]browserRuntimeEvent, 0, 8)
	for _, event := range events {
		switch event.Kind {
		case "cryptojs_utf8_parse":
			if event.Value.Value != "" {
				recentUtf8 = append(recentUtf8, event)
				if len(recentUtf8) > 8 {
					recentUtf8 = recentUtf8[len(recentUtf8)-8:]
				}
			}
		case "cryptojs_aes":
			content := browserRuntimeCryptoBlobContent(event, recentUtf8)
			if len(content) == 0 {
				continue
			}
			blobs = append(blobs, browserCaptureBlob{
				Content: content,
				Provenance: types.ExtendedProvenance{Payload: map[string]interface{}{
					"kind":   "browser_crypto",
					"path":   runtimeObservationPath(targetURL, "crypto", len(blobs)+1),
					"method": event.Method,
				}},
			})
		case "webcrypto_import_key":
			content := browserRuntimeWebCryptoBlobContent(event)
			if len(content) == 0 {
				continue
			}
			blobs = append(blobs, browserCaptureBlob{
				Content: content,
				Provenance: types.ExtendedProvenance{Payload: map[string]interface{}{
					"kind": "browser_crypto",
					"path": runtimeObservationPath(targetURL, "webcrypto", len(blobs)+1),
				}},
			})
		}
	}
	return blobs
}

func browserRuntimeCryptoBlobContent(event browserRuntimeEvent, recentUtf8 []browserRuntimeEvent) []byte {
	method := event.Method
	if method == "" {
		method = "CryptoJS.AES"
	}
	mode := normalizeCryptoMode(event.Mode)
	padding := normalizeCryptoPadding(event.Padding)
	key := event.Key.Value
	if key == "" {
		key = nearestRuntimeUtf8Candidate(recentUtf8)
	}
	if key == "" && event.Key.SigBytes > 0 {
		key = event.Key.Value
	}

	var b strings.Builder
	b.WriteString("/* LeakLens browser runtime crypto observation */\n")
	fmt.Fprintf(&b, "const leaklens_runtime_crypto_api = %q;\n", method)
	if mode != "" {
		fmt.Fprintf(&b, "const leaklens_runtime_crypto_mode = %q;\n", mode)
	}
	if padding != "" {
		fmt.Fprintf(&b, "const leaklens_runtime_crypto_padding = %q;\n", padding)
	}
	if event.Data.Value != "" {
		fmt.Fprintf(&b, "const leaklens_runtime_crypto_password = %q;\n", event.Data.Value)
	}
	if key != "" {
		fmt.Fprintf(&b, "const leaklens_runtime_crypto_key = %q;\n", key)
		if mode != "" && padding != "" {
			fmt.Fprintf(&b, "CryptoJS.AES.encrypt(leaklens_runtime_crypto_password, %q, {mode: CryptoJS.mode.%s, padding: CryptoJS.pad.%s});\n", key, mode, padding)
		}
	}
	if event.Result.Value != "" {
		fmt.Fprintf(&b, "const leaklens_runtime_crypto_ciphertext = %q;\n", event.Result.Value)
	}
	out := []byte(b.String())
	if !strings.Contains(string(out), "runtime_crypto_key") && !strings.Contains(string(out), "runtime_crypto_password") {
		return nil
	}
	return out
}

func browserRuntimeWebCryptoBlobContent(event browserRuntimeEvent) []byte {
	key := event.Key.Value
	if key == "" {
		return nil
	}
	algorithm := "AES"
	if value, ok := event.Algorithm["name"].(string); ok && value != "" {
		algorithm = value
	}
	var b strings.Builder
	b.WriteString("/* LeakLens browser runtime WebCrypto observation */\n")
	fmt.Fprintf(&b, "const leaklens_runtime_crypto_algorithm = %q;\n", algorithm)
	fmt.Fprintf(&b, "const leaklens_runtime_crypto_key = %q;\n", key)
	return []byte(b.String())
}

func nearestRuntimeUtf8Candidate(events []browserRuntimeEvent) string {
	for i := len(events) - 1; i >= 0; i-- {
		value := events[i].Value.Value
		if plausibleRuntimeCryptoKey(value) {
			return value
		}
	}
	return ""
}

func plausibleRuntimeCryptoKey(value string) bool {
	value = strings.TrimSpace(value)
	switch len(value) {
	case 8, 16, 24, 32:
	default:
		return false
	}
	hasLetter := false
	hasDigitOrSymbol := false
	for _, r := range value {
		if r <= 0x20 || r == '"' || r == '\'' || r == '\\' {
			return false
		}
		if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') {
			hasLetter = true
		} else if (r >= '0' && r <= '9') || r < 0x7f {
			hasDigitOrSymbol = true
		}
	}
	return hasLetter && hasDigitOrSymbol
}

func normalizeCryptoMode(value string) string {
	value = strings.TrimSpace(value)
	if strings.EqualFold(value, "ECB") {
		return "ECB"
	}
	if strings.EqualFold(value, "CBC") {
		return "CBC"
	}
	if strings.EqualFold(value, "GCM") {
		return "GCM"
	}
	return ""
}

func normalizeCryptoPadding(value string) string {
	value = strings.TrimSpace(value)
	if strings.EqualFold(value, "Pkcs7") {
		return "Pkcs7"
	}
	if strings.EqualFold(value, "NoPadding") {
		return "NoPadding"
	}
	if strings.EqualFold(value, "Iso97971") {
		return "Iso97971"
	}
	return ""
}

func runtimeObservationPath(targetURL, kind string, index int) string {
	parsed, err := url.Parse(targetURL)
	host := "target"
	if err == nil && parsed.Hostname() != "" {
		host = parsed.Hostname()
	}
	if index > 0 {
		return fmt.Sprintf("browser-runtime://%s/%s/%d", host, kind, index)
	}
	return fmt.Sprintf("browser-runtime://%s/%s", host, kind)
}

func browserRuntimeHookScript() string {
	return `(() => {
  if (window.__leaklensRuntimeCaptureInstalled) return;
  window.__leaklensRuntimeCaptureInstalled = true;
  let seq = 0;
  const emit = (event) => {
    try {
      event.seq = ++seq;
      console.debug("` + runtimeConsolePrefix + `" + JSON.stringify(event));
    } catch (_) {}
  };
  const valueOf = (value) => {
    const out = {type: typeof value, value: "", length: 0, sigBytes: 0};
    try {
      if (typeof value === "string") {
        out.value = value;
        out.length = value.length;
        return out;
      }
      if (value == null) return out;
      if (typeof ArrayBuffer !== "undefined" && value instanceof ArrayBuffer) {
        const bytes = new Uint8Array(value);
        out.type = "arraybuffer";
        out.length = bytes.length;
        out.value = Array.from(bytes).map(b => String.fromCharCode(b)).join("");
        return out;
      }
      if (ArrayBuffer.isView && ArrayBuffer.isView(value)) {
        const bytes = new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
        out.type = "typedarray";
        out.length = bytes.length;
        out.value = Array.from(bytes).map(b => String.fromCharCode(b)).join("");
        return out;
      }
      if (typeof value.sigBytes === "number") {
        out.type = "wordarray";
        out.sigBytes = value.sigBytes;
      }
      if (typeof value.toString === "function") {
        const rendered = value.toString();
        if (rendered && rendered !== "[object Object]") {
          out.value = rendered;
          out.length = rendered.length;
        }
      }
    } catch (_) {}
    return out;
  };
  const cryptoName = (value, fallback) => {
    try {
      if (!value) return fallback;
      if (value === window.CryptoJS?.mode?.ECB) return "ECB";
      if (value === window.CryptoJS?.mode?.CBC) return "CBC";
      if (value === window.CryptoJS?.pad?.Pkcs7) return "Pkcs7";
      if (value === window.CryptoJS?.pad?.NoPadding) return "NoPadding";
    } catch (_) {}
    return fallback;
  };
  const hookCryptoJS = (crypto) => {
    try {
      if (!crypto || crypto.__leaklensHooked) return;
      Object.defineProperty(crypto, "__leaklensHooked", {value: true, configurable: true});
      if (crypto.enc && crypto.enc.Utf8 && typeof crypto.enc.Utf8.parse === "function") {
        const originalParse = crypto.enc.Utf8.parse;
        crypto.enc.Utf8.parse = function(value) {
          emit({kind: "cryptojs_utf8_parse", method: "CryptoJS.enc.Utf8.parse", value: valueOf(value)});
          return originalParse.apply(this, arguments);
        };
      }
      if (crypto.AES) {
        ["encrypt", "decrypt"].forEach(method => {
          if (typeof crypto.AES[method] !== "function" || crypto.AES[method].__leaklensHooked) return;
          const original = crypto.AES[method];
          crypto.AES[method] = function(data, key, options) {
            let result;
            try {
              result = original.apply(this, arguments);
              return result;
            } finally {
              emit({
                kind: "cryptojs_aes",
                method: "CryptoJS.AES." + method,
                data: valueOf(data),
                key: valueOf(key),
                result: valueOf(result),
                mode: cryptoName(options && options.mode, ""),
                padding: cryptoName(options && options.padding, "")
              });
            }
          };
          Object.defineProperty(crypto.AES[method], "__leaklensHooked", {value: true, configurable: true});
        });
      }
    } catch (_) {}
  };
  const hookWebCrypto = () => {
    try {
      const subtle = window.crypto && window.crypto.subtle;
      if (!subtle || subtle.__leaklensHooked) return;
      if (typeof subtle.importKey === "function") {
        const originalImportKey = subtle.importKey.bind(subtle);
        subtle.importKey = function(format, keyData, algorithm, extractable, usages) {
          emit({kind: "webcrypto_import_key", method: "crypto.subtle.importKey", key: valueOf(keyData), algorithm, extractable, usages});
          return originalImportKey.apply(this, arguments);
        };
      }
      Object.defineProperty(subtle, "__leaklensHooked", {value: true, configurable: true});
    } catch (_) {}
  };
  let cryptoJSValue = window.CryptoJS;
  try {
    Object.defineProperty(window, "CryptoJS", {
      configurable: true,
      get() { return cryptoJSValue; },
      set(value) {
        cryptoJSValue = value;
        hookCryptoJS(value);
      }
    });
  } catch (_) {}
  const install = () => {
    hookCryptoJS(cryptoJSValue || window.CryptoJS);
    hookWebCrypto();
  };
  install();
  window.addEventListener("DOMContentLoaded", install, true);
  window.addEventListener("load", install, true);
  setInterval(install, 100);
})();`
}
