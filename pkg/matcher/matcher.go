package matcher

import "github.com/dinosn/leaklens/pkg/types"

// Matcher scans content for rule matches.
type Matcher interface {
	// Match scans content against all loaded rules.
	// Returns matches with offsets and capture groups.
	Match(content []byte) ([]*types.Match, error)

	// MatchWithBlobID scans content with a known BlobID.
	MatchWithBlobID(content []byte, blobID types.BlobID) ([]*types.Match, error)

	// Close releases resources (e.g., Hyperscan scratch space).
	Close() error
}

// AESCiphertextEvidence is owner-supplied ciphertext used to validate a
// detected AES-ECB/PKCS7 password wrapper without performing a live request.
type AESCiphertextEvidence struct {
	Ciphertext []byte
	Source     string
}

// Config for matcher initialization.
type Config struct {
	// Rules to compile and load into the matcher
	Rules []*types.Rule

	// MaxMatchesPerBlob limits matches returned per blob (0 = unlimited)
	MaxMatchesPerBlob int

	// ContextLines is the number of lines of context to extract before/after matches (0 = none)
	ContextLines int

	// AESCiphertexts are optional owner-supplied ciphertexts to decrypt with
	// keys from proven AES-ECB/PKCS7 password flows.
	AESCiphertexts []AESCiphertextEvidence
}
