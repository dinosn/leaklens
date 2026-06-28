package enum

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

var tlsFallbackWarningAuthorities sync.Map

func newTLSFallbackHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout:   timeout,
		Transport: newTLSFallbackTransport(),
	}
}

func newTLSFallbackTransport() http.RoundTripper {
	primary := http.DefaultTransport.(*http.Transport).Clone()
	insecure := http.DefaultTransport.(*http.Transport).Clone()
	tlsConfig := &tls.Config{}
	if insecure.TLSClientConfig != nil {
		tlsConfig = insecure.TLSClientConfig.Clone()
	}
	// #nosec G402 -- LeakLens intentionally retries crawler asset downloads
	// after warning when a target site has a certificate verification problem.
	tlsConfig.InsecureSkipVerify = true
	insecure.TLSClientConfig = tlsConfig

	return &tlsFallbackTransport{
		primary:  primary,
		insecure: insecure,
	}
}

type tlsFallbackTransport struct {
	primary  http.RoundTripper
	insecure http.RoundTripper
}

func (t *tlsFallbackTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.primary.RoundTrip(req)
	if err == nil || !isTLSCertificateVerificationError(err) {
		return resp, err
	}

	retryReq, retryErr := cloneRequestForRetry(req)
	if retryErr != nil {
		return resp, err
	}

	if req.URL != nil {
		authority := req.URL.Scheme + "://" + req.URL.Host
		if _, loaded := tlsFallbackWarningAuthorities.LoadOrStore(authority, struct{}{}); !loaded {
			warnf("warning: TLS certificate verification failed for %s; retrying without certificate verification: %v\n", authority, err)
		}
	}

	return t.insecure.RoundTrip(retryReq)
}

func cloneRequestForRetry(req *http.Request) (*http.Request, error) {
	retryReq := req.Clone(req.Context())
	if req.Body == nil {
		return retryReq, nil
	}
	if req.GetBody == nil {
		return nil, fmt.Errorf("request body cannot be replayed")
	}
	body, err := req.GetBody()
	if err != nil {
		return nil, err
	}
	retryReq.Body = body
	return retryReq, nil
}

func isTLSCertificateVerificationError(err error) bool {
	if err == nil {
		return false
	}

	var tlsVerifyErr *tls.CertificateVerificationError
	if errors.As(err, &tlsVerifyErr) {
		return true
	}

	var unknownAuthorityErr x509.UnknownAuthorityError
	if errors.As(err, &unknownAuthorityErr) {
		return true
	}

	var hostnameErr x509.HostnameError
	if errors.As(err, &hostnameErr) {
		return true
	}

	var invalidErr x509.CertificateInvalidError
	if errors.As(err, &invalidErr) {
		return true
	}

	var systemRootsErr x509.SystemRootsError
	if errors.As(err, &systemRootsErr) {
		return true
	}

	var urlErr *url.Error
	if errors.As(err, &urlErr) && urlErr.Err != nil && urlErr.Err != err {
		return isTLSCertificateVerificationError(urlErr.Err)
	}

	message := err.Error()
	return strings.Contains(message, "tls: failed to verify certificate") ||
		strings.Contains(message, "x509:")
}
