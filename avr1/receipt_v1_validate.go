package avr1

import (
	"crypto/ed25519"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/verirelay/protocol/internal/wire"
)

var sha256HexPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

func invalidReceipt(detail string) error {
	return fmt.Errorf("%w: %s", errInvalidSignedReceipt, detail)
}

func validateSignedReceiptPayload(receipt SignedReceiptV1) error {
	if err := validateVersion(receipt.Version); err != nil {
		return err
	}
	if receipt.Canonicalization != avrCanonicalization || receipt.SignatureAlgorithm != AVRSignatureAlgorithm || receipt.HashAlgorithm != avrHashAlgorithm {
		return invalidReceipt("algorithm identifiers")
	}
	if receipt.RequestID == "" || receipt.Method == "" || receipt.UpstreamAuthority == "" || receipt.UpstreamPath == "" || receipt.UpstreamTLS.SNI == "" || receipt.ServicePublicKey == "" || receipt.KeyID == "" {
		return invalidReceipt("missing required field")
	}
	if err := validateUTCTimestamp(receipt.Timestamp); err != nil {
		return err
	}
	if receipt.ResponseStatus < 100 || receipt.ResponseStatus > 599 {
		return invalidReceipt("response_status must be from 100 to 599")
	}
	for _, digest := range []struct{ field, value string }{
		{"request_body_sha256", receipt.RequestBodySHA256},
		{"response_body_sha256", receipt.ResponseBodySHA256},
		{"upstream_tls.spki_sha256", receipt.UpstreamTLS.SPKISHA256},
	} {
		if !sha256HexPattern.MatchString(digest.value) {
			return invalidReceipt(digest.field)
		}
	}
	return validateKeyID(receipt.ServicePublicKey, receipt.KeyID)
}

func validateVersion(version string) error {
	if version == AVRVersion {
		return nil
	}
	if strings.HasPrefix(version, "avr/") {
		return errUnsupportedAVRVersion
	}
	return invalidReceipt("version")
}

func validateKeyID(servicePublicKey, keyID string) error {
	publicKey, err := decodeBase64URL(servicePublicKey, ed25519.PublicKeySize, "service_public_key")
	if err != nil {
		return err
	}
	if keyID != ReceiptKeyID(ed25519.PublicKey(publicKey)) {
		return invalidReceipt("key_id")
	}
	return nil
}

func validateUTCTimestamp(value string) error {
	if !strings.HasSuffix(value, "Z") {
		return invalidReceipt("timestamp must use UTC Z")
	}
	if _, err := time.Parse(time.RFC3339Nano, value); err != nil {
		return invalidReceipt("timestamp")
	}
	return nil
}

// decodeBase64URL decodes canonical unpadded base64url of exactly wantLen
// bytes, naming the field in errors.
func decodeBase64URL(value string, wantLen int, name string) ([]byte, error) {
	decoded, err := wire.DecodeBase64URL(value)
	if err != nil {
		return nil, invalidReceipt(name)
	}
	if len(decoded) != wantLen {
		return nil, invalidReceipt(name + " length")
	}
	return decoded, nil
}
