// Package avr1 defines the avr/1 contract of VeriRelay: the signed Receipt it
// issues for every forwarded Upstream request, the SEV-SNP REPORT_DATA that
// binds the Receipt Signing Key, the attestation response that discloses it,
// the Receipt Evidence Bundle, and the Raw Capture envelope.
package avr1

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/verirelay/protocol/internal/wire"
)

// Identifiers and sizes fixed by the avr/1 receipt format. AVRVersion and
// AVRSignatureAlgorithm are the version and signature_algorithm values of
// every receipt; AVRNonceBytes is the nonce length ReportDataAVR1 requires.
const (
	AVRVersion            = "avr/1"
	AVRSignatureAlgorithm = "ed25519"
	AVRNonceBytes         = 32
)

// avrCanonicalization and avrHashAlgorithm are the canonicalization and
// hash_algorithm values of every receipt.
const (
	avrCanonicalization = "jcs-rfc8785"
	avrHashAlgorithm    = "sha256"
)

// Errors returned by receipt validation and verification.
// errUnsupportedAVRVersion is returned for a version that starts with "avr/"
// but is not AVRVersion. errInvalidSignedReceipt is wrapped by the validation
// errors for malformed receipts and receipt inputs. errInvalidSignature is
// returned, possibly wrapped, when payload_sha256 does not match the payload
// or the Ed25519 signature does not verify.
var (
	errUnsupportedAVRVersion = errors.New("unsupported avr version")
	errInvalidSignedReceipt  = errors.New("invalid signed receipt")
	errInvalidSignature      = errors.New("invalid receipt signature")
)

// SignedReceiptV1 is an avr/1 signed receipt. The signature covers the JCS
// canonical form of the receipt with Signature omitted.
type SignedReceiptV1 struct {
	Version            string                `json:"version"`
	Canonicalization   string                `json:"canonicalization"`
	SignatureAlgorithm string                `json:"signature_algorithm"`
	HashAlgorithm      string                `json:"hash_algorithm"`
	RequestID          string                `json:"request_id"`
	Timestamp          string                `json:"timestamp"`
	Method             string                `json:"method"`
	UpstreamAuthority  string                `json:"upstream_authority"`
	UpstreamPath       string                `json:"upstream_path"`
	RequestBodySHA256  string                `json:"request_body_sha256"`
	ResponseBodySHA256 string                `json:"response_body_sha256"`
	ResponseStatus     int                   `json:"response_status"`
	UpstreamTLS        UpstreamTLSIdentityV1 `json:"upstream_tls"`
	ServicePublicKey   string                `json:"service_public_key"`
	KeyID              string                `json:"key_id"`
	Signature          *ReceiptSignatureV1   `json:"signature,omitempty"`
}

// UpstreamTLSIdentityV1 identifies the upstream TLS endpoint of a receipt: the
// SNI and the hex SHA-256 of the upstream certificate's SPKI.
type UpstreamTLSIdentityV1 struct {
	SNI        string `json:"sni"`
	SPKISHA256 string `json:"spki_sha256"`
}

// ReceiptSignatureV1 is the signature of a SignedReceiptV1: the hex SHA-256 of
// the signed payload and the unpadded base64url Ed25519 signature over it.
type ReceiptSignatureV1 struct {
	PayloadSHA256 string `json:"payload_sha256"`
	Value         string `json:"value"`
}

// ReceiptFactsV1 holds the per-request facts BuildSignedReceiptV1 copies into
// a SignedReceiptV1.
type ReceiptFactsV1 struct {
	RequestID          string
	Timestamp          string
	Method             string
	UpstreamAuthority  string
	UpstreamPath       string
	SNI                string
	UpstreamSPKISHA256 string
	RequestBodySHA256  string
	ResponseBodySHA256 string
	ResponseStatus     int
}

// ReceiptSignerV1 signs avr/1 receipts with an Ed25519 key.
type ReceiptSignerV1 struct {
	private ed25519.PrivateKey
	public  ed25519.PublicKey
	keyID   string
}

// NewReceiptSignerV1 returns a signer for private, which may be a 32-byte
// Ed25519 seed or a 64-byte Ed25519 private key; any other length is an error.
func NewReceiptSignerV1(private ed25519.PrivateKey) (*ReceiptSignerV1, error) {
	if len(private) == ed25519.SeedSize {
		private = ed25519.NewKeyFromSeed(private)
	}
	if len(private) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid ed25519 private key length: %d", len(private))
	}
	public := private.Public().(ed25519.PublicKey)
	return &ReceiptSignerV1{private: private, public: public, keyID: ReceiptKeyID(public)}, nil
}

// KeyID returns the signer's key id, ReceiptKeyID of its public key.
func (s *ReceiptSignerV1) KeyID() string {
	return s.keyID
}

// PublicKeyBase64URL returns the signer's public key as unpadded base64url.
func (s *ReceiptSignerV1) PublicKeyBase64URL() string {
	return wire.EncodeBase64URL(s.public)
}

// Sign sets the avr/1 identifiers, ServicePublicKey and KeyID on receipt, then
// signs the JCS canonical form of receipt with Signature omitted and stores
// the result in receipt.Signature.
func (s *ReceiptSignerV1) Sign(receipt *SignedReceiptV1) error {
	receipt.Version = AVRVersion
	receipt.Canonicalization = avrCanonicalization
	receipt.SignatureAlgorithm = AVRSignatureAlgorithm
	receipt.HashAlgorithm = avrHashAlgorithm
	receipt.ServicePublicKey = s.PublicKeyBase64URL()
	receipt.KeyID = s.KeyID()
	payloadHash, payload, err := canonicalSignedReceiptPayload(*receipt)
	if err != nil {
		return err
	}
	sig := ed25519.Sign(s.private, payload)
	receipt.Signature = &ReceiptSignatureV1{
		PayloadSHA256: payloadHash,
		Value:         wire.EncodeBase64URL(sig),
	}
	return nil
}

// BuildSignedReceiptV1 builds a SignedReceiptV1 from facts and signs it with
// signer.
func BuildSignedReceiptV1(facts ReceiptFactsV1, signer *ReceiptSignerV1) (SignedReceiptV1, error) {
	if signer == nil {
		return SignedReceiptV1{}, invalidReceipt("missing signer")
	}
	receipt := SignedReceiptV1{
		RequestID:          facts.RequestID,
		Timestamp:          facts.Timestamp,
		Method:             facts.Method,
		UpstreamAuthority:  facts.UpstreamAuthority,
		UpstreamPath:       facts.UpstreamPath,
		RequestBodySHA256:  facts.RequestBodySHA256,
		ResponseBodySHA256: facts.ResponseBodySHA256,
		ResponseStatus:     facts.ResponseStatus,
		UpstreamTLS:        UpstreamTLSIdentityV1{SNI: facts.SNI, SPKISHA256: facts.UpstreamSPKISHA256},
	}
	if err := signer.Sign(&receipt); err != nil {
		return SignedReceiptV1{}, err
	}
	return receipt, nil
}

// ReceiptKeyID returns the hex encoding of the first 8 bytes of
// SHA-256(public).
func ReceiptKeyID(public ed25519.PublicKey) string {
	sum := sha256.Sum256(public)
	return hex.EncodeToString(sum[:8])
}

// canonicalSignedReceiptPayload validates receipt and returns its signing
// payload, the JCS canonical form (canonicalize) of receipt with Signature
// omitted, together with the payload's hex SHA-256 (returned first).
func canonicalSignedReceiptPayload(receipt SignedReceiptV1) (string, []byte, error) {
	receipt.Signature = nil
	if err := validateSignedReceiptPayload(receipt); err != nil {
		return "", nil, err
	}
	payload, err := canonicalize(receipt)
	if err != nil {
		return "", nil, err
	}
	return SHA256Hex(payload), payload, nil
}

// DecodeSignedReceiptV1 decodes a Receipt strictly: data must be one JSON
// object without duplicate keys and without fields beyond those of
// SignedReceiptV1, at any depth, and signature must not be null. It does not
// check field values or the signature; call VerifySignedReceiptV1 for that.
//
// For every decoded Receipt that VerifySignedReceiptV1 accepts, the payload
// it verifies equals the JCS canonical form of data without signature.
func DecodeSignedReceiptV1(data []byte) (SignedReceiptV1, error) {
	var receipt SignedReceiptV1
	if err := wire.DecodeStrict(data, &receipt); err != nil {
		return SignedReceiptV1{}, fmt.Errorf("%w: %w", errInvalidSignedReceipt, err)
	}
	return receipt, nil
}

// VerifySignedReceiptV1 checks every field rule of receipt, that it has a
// Signature, that Signature.PayloadSHA256 matches the payload hash, and that
// Signature.Value is a valid Ed25519 signature of the payload under
// ServicePublicKey.
func VerifySignedReceiptV1(receipt SignedReceiptV1) error {
	if receipt.Signature == nil {
		return invalidReceipt("missing signature")
	}
	payloadHash, payload, err := canonicalSignedReceiptPayload(receipt)
	if err != nil {
		return err
	}
	if receipt.Signature.PayloadSHA256 != payloadHash {
		return fmt.Errorf("%w: payload hash mismatch", errInvalidSignature)
	}
	publicKey, err := decodeBase64URL(receipt.ServicePublicKey, ed25519.PublicKeySize, "service_public_key")
	if err != nil {
		return err
	}
	sig, err := decodeBase64URL(receipt.Signature.Value, ed25519.SignatureSize, "signature.value")
	if err != nil {
		return err
	}
	if !ed25519.Verify(ed25519.PublicKey(publicKey), payload, sig) {
		return errInvalidSignature
	}
	return nil
}

// VerifySignedReceiptJSONV1 decodes data with DecodeSignedReceiptV1, verifies
// the result with VerifySignedReceiptV1, and returns the verified Receipt.
func VerifySignedReceiptJSONV1(data []byte) (SignedReceiptV1, error) {
	receipt, err := DecodeSignedReceiptV1(data)
	if err != nil {
		return SignedReceiptV1{}, err
	}
	if err := VerifySignedReceiptV1(receipt); err != nil {
		return SignedReceiptV1{}, err
	}
	return receipt, nil
}
