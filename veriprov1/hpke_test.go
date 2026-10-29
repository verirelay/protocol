package veriprov1

import (
	"encoding/json"
	"os"
	"testing"
)

type hpkeGolden struct {
	RecipientPrivateKey string     `json:"recipient_private_key_base64url"`
	RecipientPublicKey  string     `json:"recipient_public_key_base64url"`
	AAD                 AADContext `json:"aad"`
	Enc                 string     `json:"enc_base64url"`
	Ciphertext          string     `json:"ciphertext_base64url"`
	Plaintext           string     `json:"plaintext_base64url"`
}

func TestHPKEOpenGoldenVector(t *testing.T) {
	golden := readHPKEGolden(t)
	privateKey, err := DecodeBase64URL(golden.RecipientPrivateKey, "private_key", X25519PublicKeySize)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := DecodeBase64URL(golden.Plaintext, "plaintext", -1)
	if err != nil {
		t.Fatal(err)
	}
	envelope := HPKEEnvelope{Version: ProtocolVersion, ChallengeID: golden.AAD.ChallengeID, Enc: golden.Enc, Ciphertext: golden.Ciphertext, AAD: golden.AAD}
	got, err := Open(privateKey, envelope)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(plaintext) {
		t.Fatalf("plaintext = %q, want %q", got, plaintext)
	}
	envelope.Ciphertext = envelope.Ciphertext[:len(envelope.Ciphertext)-1] + "A"
	if _, err := Open(privateKey, envelope); err == nil {
		t.Fatal("accepted modified ciphertext")
	}
}

func TestHPKESealRoundTrip(t *testing.T) {
	golden := readHPKEGolden(t)
	publicKey, err := DecodeBase64URL(golden.RecipientPublicKey, "public_key", X25519PublicKeySize)
	if err != nil {
		t.Fatal(err)
	}
	privateKey, err := DecodeBase64URL(golden.RecipientPrivateKey, "private_key", X25519PublicKeySize)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := DecodeBase64URL(golden.Plaintext, "plaintext", -1)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := Seal(publicKey, plaintext, golden.AAD)
	if err != nil {
		t.Fatal(err)
	}
	if envelope.Signature != "" {
		t.Fatalf("Seal signed the envelope: %q", envelope.Signature)
	}
	got, err := Open(privateKey, envelope)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(plaintext) {
		t.Fatalf("plaintext = %q, want %q", got, plaintext)
	}
}

func readHPKEGolden(t *testing.T) hpkeGolden {
	t.Helper()
	data, err := os.ReadFile("testdata/hpke_golden.json")
	if err != nil {
		t.Fatal(err)
	}
	var golden hpkeGolden
	if err := json.Unmarshal(data, &golden); err != nil {
		t.Fatal(err)
	}
	return golden
}
