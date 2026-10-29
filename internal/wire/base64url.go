package wire

import (
	"encoding/base64"
	"errors"
)

// DecodeBase64URL decodes value as canonical unpadded base64url: the only
// encoding EncodeBase64URL produces for the decoded bytes.
func DecodeBase64URL(value string) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || EncodeBase64URL(decoded) != value {
		return nil, errors.New("must be canonical unpadded base64url")
	}
	return decoded, nil
}

// EncodeBase64URL returns value as unpadded base64url.
func EncodeBase64URL(value []byte) string {
	return base64.RawURLEncoding.EncodeToString(value)
}
