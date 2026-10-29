package veriprov1

import (
	"crypto/ed25519"
	"errors"
	"fmt"
)

// envelopeSignatureContext starts the message an envelope signature covers.
const envelopeSignatureContext = "veriprov/1\x00envelope\x00"

// AADContext is the HPKE additional authenticated data of an envelope.
type AADContext struct {
	Protocol    string `json:"protocol"`
	ChallengeID string `json:"challenge_id"`
}

// validate requires Protocol to be ProtocolVersion and a valid challenge ID.
func (aad AADContext) validate() error {
	if aad.Protocol != ProtocolVersion {
		return fmt.Errorf("protocol = %q, want %q", aad.Protocol, ProtocolVersion)
	}
	return validateChallengeID(aad.ChallengeID)
}

// Bytes validates aad and returns its json.Marshal encoding (not JCS), the AAD
// bytes passed to HPKE.
func (aad AADContext) Bytes() ([]byte, error) {
	if err := aad.validate(); err != nil {
		return nil, err
	}
	return MarshalJSON(aad)
}

// HPKEEnvelope is an HPKE ciphertext with its encapsulated key and AAD context,
// signed with the VeriProv identity key.
type HPKEEnvelope struct {
	Version     string     `json:"version"`
	ChallengeID string     `json:"challenge_id"`
	Enc         string     `json:"enc"`
	Ciphertext  string     `json:"ciphertext"`
	AAD         AADContext `json:"aad"`
	Signature   string     `json:"signature"`
}

// sealed checks the version, the challenge ID, an X25519PublicKeySize-byte
// enc, a base64url ciphertext and the AAD, and that the AAD challenge ID
// equals ChallengeID. It returns the decoded enc and ciphertext.
func (envelope HPKEEnvelope) sealed() (enc, ciphertext []byte, err error) {
	if envelope.Version != ProtocolVersion {
		return nil, nil, fmt.Errorf("version = %q, want %q", envelope.Version, ProtocolVersion)
	}
	if err := validateChallengeID(envelope.ChallengeID); err != nil {
		return nil, nil, err
	}
	if enc, err = DecodeBase64URL(envelope.Enc, "enc", X25519PublicKeySize); err != nil {
		return nil, nil, err
	}
	if ciphertext, err = DecodeBase64URL(envelope.Ciphertext, "ciphertext", -1); err != nil {
		return nil, nil, err
	}
	if err := envelope.AAD.validate(); err != nil {
		return nil, nil, fmt.Errorf("aad: %w", err)
	}
	if envelope.AAD.ChallengeID != envelope.ChallengeID {
		return nil, nil, errors.New("envelope challenge_id must match aad")
	}
	return enc, ciphertext, nil
}

// validate checks the sealed fields and a signature of ed25519.SignatureSize
// bytes.
func (envelope HPKEEnvelope) validate() error {
	if _, _, err := envelope.sealed(); err != nil {
		return err
	}
	_, err := DecodeBase64URL(envelope.Signature, "signature", ed25519.SignatureSize)
	return err
}

// signatureMessage validates the sealed fields and returns the message an
// envelope signature covers:
//
//	"veriprov/1\x00envelope\x00" || challenge_id || 0x00 || enc || ciphertext
//
// challenge_id is the string as sent; enc and ciphertext are the decoded bytes.
func (envelope HPKEEnvelope) signatureMessage() ([]byte, error) {
	enc, ciphertext, err := envelope.sealed()
	if err != nil {
		return nil, err
	}
	message := make([]byte, 0, len(envelopeSignatureContext)+len(envelope.ChallengeID)+1+len(enc)+len(ciphertext))
	message = append(message, envelopeSignatureContext...)
	message = append(message, envelope.ChallengeID...)
	message = append(message, 0)
	message = append(message, enc...)
	message = append(message, ciphertext...)
	return message, nil
}

// SignEnvelope sets envelope.Signature to the Ed25519 signature under the
// VeriProv identity key priv of the envelope's signature message.
func SignEnvelope(priv ed25519.PrivateKey, envelope *HPKEEnvelope) error {
	if len(priv) != ed25519.PrivateKeySize {
		return fmt.Errorf("identity private key length = %d, want %d", len(priv), ed25519.PrivateKeySize)
	}
	message, err := envelope.signatureMessage()
	if err != nil {
		return err
	}
	envelope.Signature = EncodeBase64URL(ed25519.Sign(priv, message))
	return nil
}

// VerifyEnvelopeSignature checks envelope.Signature against the VeriProv
// identity public key pub, which a Guest takes from its Bootstrap. A Guest
// verifies the signature before it opens the envelope.
func VerifyEnvelopeSignature(pub ed25519.PublicKey, envelope HPKEEnvelope) error {
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("identity public key length = %d, want %d", len(pub), ed25519.PublicKeySize)
	}
	message, err := envelope.signatureMessage()
	if err != nil {
		return err
	}
	signature, err := DecodeBase64URL(envelope.Signature, "signature", ed25519.SignatureSize)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, message, signature) {
		return errors.New("envelope signature does not verify")
	}
	return nil
}
