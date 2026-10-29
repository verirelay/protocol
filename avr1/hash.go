package avr1

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/verirelay/protocol/internal/wire"
)

// SHA256Hex returns the lowercase hex SHA-256 of data.
func SHA256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// DecodeBase64URL decodes value as canonical unpadded base64url, the encoding
// of every binary avr/1 value.
func DecodeBase64URL(value string) ([]byte, error) {
	return wire.DecodeBase64URL(value)
}
