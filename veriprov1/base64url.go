package veriprov1

import (
	"fmt"

	"github.com/verirelay/protocol/internal/wire"
)

// EncodeBase64URL returns value as unpadded base64url.
func EncodeBase64URL(value []byte) string {
	return wire.EncodeBase64URL(value)
}

// DecodeBase64URL decodes value as non-empty, canonical, unpadded base64url,
// naming field in errors. The decoded length must equal expectedLength unless
// expectedLength is negative.
func DecodeBase64URL(value, field string, expectedLength int) ([]byte, error) {
	if value == "" {
		return nil, fmt.Errorf("%s must not be empty", field)
	}
	decoded, err := wire.DecodeBase64URL(value)
	if err != nil {
		return nil, fmt.Errorf("%s %w", field, err)
	}
	if expectedLength >= 0 && len(decoded) != expectedLength {
		return nil, fmt.Errorf("%s decoded length = %d, want %d", field, len(decoded), expectedLength)
	}
	return decoded, nil
}

// decodeBase64URLMinSize decodes value with no fixed length requirement and
// additionally requires the decoded bytes to be at least minSize long.
func decodeBase64URLMinSize(value, field string, minSize int) ([]byte, error) {
	decoded, err := DecodeBase64URL(value, field, -1)
	if err != nil {
		return nil, err
	}
	if len(decoded) < minSize {
		return nil, fmt.Errorf("%s decoded length = %d, want at least %d", field, len(decoded), minSize)
	}
	return decoded, nil
}
