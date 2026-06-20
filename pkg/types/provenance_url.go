package types

// URLProvenance tracks content downloaded from an HTTP(S) URL.
type URLProvenance struct {
	URL string
}

// Kind returns "url".
func (u URLProvenance) Kind() string {
	return "url"
}

// Path returns the original URL.
func (u URLProvenance) Path() string {
	return u.URL
}
