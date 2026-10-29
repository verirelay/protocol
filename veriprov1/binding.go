// Package veriprov1 defines the veriprov/1 Provisioning contract between
// VeriProv and the VeriRelay Guest: the challenge and provision messages, the
// REPORT_DATA binding of the Guest's provisioning key, the signed HPKE
// envelope, the Runtime Config, the decoding rules and the error codes.
package veriprov1

import (
	"crypto/sha512"
	"fmt"
)

// Protocol constants of veriprov/1. ProtocolVersion is the protocol
// identifier; NonceSize, X25519PublicKeySize, MinimumChallengeIDSize and
// AttestationReportSize are the byte lengths of the challenge nonce, a raw
// X25519 public key, the shortest challenge ID and a raw AMD SEV-SNP
// attestation report.
const (
	ProtocolVersion        = "veriprov/1"
	NonceSize              = 32
	X25519PublicKeySize    = 32
	MinimumChallengeIDSize = 16
	AttestationReportSize  = 1184
)

// bindingInput returns the REPORT_DATA preimage ProtocolVersion || 0x00 ||
// nonce || publicKey. nonce must be NonceSize bytes and publicKey
// X25519PublicKeySize bytes.
func bindingInput(nonce, publicKey []byte) ([]byte, error) {
	if len(nonce) != NonceSize {
		return nil, fmt.Errorf("nonce length = %d, want %d", len(nonce), NonceSize)
	}
	if len(publicKey) != X25519PublicKeySize {
		return nil, fmt.Errorf("provisioning public key length = %d, want %d", len(publicKey), X25519PublicKeySize)
	}
	input := make([]byte, 0, len(ProtocolVersion)+1+NonceSize+X25519PublicKeySize)
	input = append(input, ProtocolVersion...)
	input = append(input, 0)
	input = append(input, nonce...)
	input = append(input, publicKey...)
	return input, nil
}

// ReportData returns SHA-512("veriprov/1" || 0x00 || nonce || publicKey), the
// REPORT_DATA that binds publicKey to the challenge nonce.
func ReportData(nonce, publicKey []byte) ([sha512.Size]byte, error) {
	input, err := bindingInput(nonce, publicKey)
	if err != nil {
		return [sha512.Size]byte{}, err
	}
	return sha512.Sum512(input), nil
}
