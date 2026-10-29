package avr1

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/verirelay/protocol/internal/wire"
)

// ReceiptEvidenceBundle is the Receipt Evidence Bundle: a Receipt and the
// attestation response archived for its Receipt Signing Key, or a nil
// Attestation when none is archived.
type ReceiptEvidenceBundle struct {
	Version     string               `json:"version"`
	Receipt     SignedReceiptV1      `json:"receipt"`
	Attestation *AttestationResponse `json:"attestation"`
}

// DecodeReceiptEvidenceBundle decodes a Receipt Evidence Bundle. The bundle
// object and attestation are decoded leniently, so unknown fields are ignored,
// and the receipt strictly with DecodeSignedReceiptV1; duplicate keys are
// rejected everywhere. version must be AVRVersion and receipt must be present;
// attestation may be null or absent. It neither verifies the Receipt nor
// checks the attestation.
func DecodeReceiptEvidenceBundle(data []byte) (ReceiptEvidenceBundle, error) {
	var raw struct {
		Version     string          `json:"version"`
		Receipt     json.RawMessage `json:"receipt"`
		Attestation json.RawMessage `json:"attestation"`
	}
	if err := wire.DecodeLenient(data, &raw); err != nil {
		return ReceiptEvidenceBundle{}, err
	}
	if raw.Version != AVRVersion {
		return ReceiptEvidenceBundle{}, fmt.Errorf("version = %q, want %q", raw.Version, AVRVersion)
	}
	if isNullOrAbsent(raw.Receipt) {
		return ReceiptEvidenceBundle{}, errors.New("receipt is required")
	}
	receipt, err := DecodeSignedReceiptV1(raw.Receipt)
	if err != nil {
		return ReceiptEvidenceBundle{}, fmt.Errorf("receipt: %w", err)
	}
	bundle := ReceiptEvidenceBundle{Version: raw.Version, Receipt: receipt}
	if !isNullOrAbsent(raw.Attestation) {
		attestation, err := DecodeAttestationResponse(raw.Attestation)
		if err != nil {
			return ReceiptEvidenceBundle{}, fmt.Errorf("attestation: %w", err)
		}
		bundle.Attestation = &attestation
	}
	return bundle, nil
}

func isNullOrAbsent(value json.RawMessage) bool {
	return value == nil || bytes.Equal(value, []byte("null"))
}
