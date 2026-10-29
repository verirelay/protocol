package avr1

import (
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/binary"
	"io"
)

// avrReportDataDomainSeparator is the domain-separation prefix, including its
// trailing NUL byte, that starts the ReportDataAVR1 hash input.
const avrReportDataDomainSeparator = "VeriRelay-AVR-REPORT-DATA/1\x00"

// ReportDataAVR1 returns the SEV-SNP REPORT_DATA binding a receipt signing key
// to nonce: SHA-512 of the domain separator "VeriRelay-AVR-REPORT-DATA/1\x00"
// followed by AVRVersion, AVRSignatureAlgorithm, publicKey and nonce, each
// prefixed with its length as a 4-byte big-endian integer. publicKey must be an
// Ed25519 public key and nonce exactly AVRNonceBytes long; otherwise it returns
// an error.
func ReportDataAVR1(publicKey ed25519.PublicKey, nonce []byte) ([64]byte, error) {
	var zero [64]byte
	if len(publicKey) != ed25519.PublicKeySize {
		return zero, invalidReceipt("receipt_signing_public_key length")
	}
	if len(nonce) != AVRNonceBytes {
		return zero, invalidReceipt("nonce length")
	}
	h := sha512.New()
	_, _ = h.Write([]byte(avrReportDataDomainSeparator))
	writeLengthPrefixed(h, []byte(AVRVersion))
	writeLengthPrefixed(h, []byte(AVRSignatureAlgorithm))
	writeLengthPrefixed(h, publicKey)
	writeLengthPrefixed(h, nonce)
	var out [64]byte
	copy(out[:], h.Sum(nil))
	return out, nil
}

// DecodeNonceBase64URL decodes an unpadded base64url nonce and requires it to
// be exactly AVRNonceBytes long.
func DecodeNonceBase64URL(value string) ([]byte, error) {
	return decodeBase64URL(value, AVRNonceBytes, "nonce")
}

// DecodeEd25519PublicKeyBase64URL decodes an unpadded base64url Ed25519 public
// key and requires it to be ed25519.PublicKeySize bytes.
func DecodeEd25519PublicKeyBase64URL(value string) (ed25519.PublicKey, error) {
	decoded, err := decodeBase64URL(value, ed25519.PublicKeySize, "receipt_signing_public_key")
	if err != nil {
		return nil, err
	}
	return ed25519.PublicKey(decoded), nil
}

func writeLengthPrefixed(w io.Writer, value []byte) {
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(value))) //nolint:gosec // G115: callers pass only fixed-size values (AVRVersion, AVRSignatureAlgorithm, a 32-byte key, an AVRNonceBytes nonce)
	_, _ = w.Write(lenBuf[:])
	_, _ = w.Write(value)
}
