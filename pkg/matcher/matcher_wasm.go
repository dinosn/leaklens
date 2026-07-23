//go:build wasm

package matcher

// New creates a regexp-based matcher for WASM builds.
func New(cfg Config) (Matcher, error) {
	base, err := NewRegexp(cfg.Rules, cfg.ContextLines)
	if err != nil {
		return nil, err
	}
	return newPostProcessingMatcher(base, cfg), nil
}
