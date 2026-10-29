package veriprov1

import (
	"crypto/ecdh"
	"crypto/hpke"
	"fmt"
)

// HPKEInfo is the HPKE info string Seal and Open pass.
const HPKEInfo = "veriprov/1\x00runtime-config"

var (
	kem  = hpke.DHKEM(ecdh.X25519())
	kdf  = hpke.HKDFSHA256()
	aead = hpke.ChaCha20Poly1305()
)

// Seal encrypts plaintext for recipientPublicKey under the veriprov/1 suite
// (DHKEM-X25519, HKDF-SHA256, ChaCha20-Poly1305) with the AAD context bound in.
// The returned envelope is unsigned; sign it with SignEnvelope.
func Seal(recipientPublicKey, plaintext []byte, aad AADContext) (HPKEEnvelope, error) {
	if len(recipientPublicKey) != X25519PublicKeySize {
		return HPKEEnvelope{}, fmt.Errorf("recipient public key length = %d, want %d", len(recipientPublicKey), X25519PublicKeySize)
	}
	aadBytes, err := aad.Bytes()
	if err != nil {
		return HPKEEnvelope{}, err
	}
	publicKey, err := kem.NewPublicKey(recipientPublicKey)
	if err != nil {
		return HPKEEnvelope{}, fmt.Errorf("parse recipient public key: %w", err)
	}
	enc, sender, err := hpke.NewSender(publicKey, kdf, aead, []byte(HPKEInfo))
	if err != nil {
		return HPKEEnvelope{}, fmt.Errorf("create hpke sender: %w", err)
	}
	ciphertext, err := sender.Seal(aadBytes, plaintext)
	if err != nil {
		return HPKEEnvelope{}, fmt.Errorf("hpke seal: %w", err)
	}
	envelope := HPKEEnvelope{
		Version:     ProtocolVersion,
		ChallengeID: aad.ChallengeID,
		Enc:         EncodeBase64URL(enc),
		Ciphertext:  EncodeBase64URL(ciphertext),
		AAD:         aad,
	}
	if _, _, err := envelope.sealed(); err != nil {
		return HPKEEnvelope{}, err
	}
	return envelope, nil
}

// Open decrypts envelope with recipientPrivateKey, checking the AAD context.
// It does not check the signature; call VerifyEnvelopeSignature first.
func Open(recipientPrivateKey []byte, envelope HPKEEnvelope) ([]byte, error) {
	if len(recipientPrivateKey) != X25519PublicKeySize {
		return nil, fmt.Errorf("recipient private key length = %d, want %d", len(recipientPrivateKey), X25519PublicKeySize)
	}
	enc, ciphertext, err := envelope.sealed()
	if err != nil {
		return nil, err
	}
	aad, err := envelope.AAD.Bytes()
	if err != nil {
		return nil, err
	}
	privateKey, err := kem.NewPrivateKey(recipientPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("parse recipient private key: %w", err)
	}
	recipient, err := hpke.NewRecipient(enc, privateKey, kdf, aead, []byte(HPKEInfo))
	if err != nil {
		return nil, fmt.Errorf("create hpke recipient: %w", err)
	}
	plaintext, err := recipient.Open(aad, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("hpke open: %w", err)
	}
	return plaintext, nil
}
