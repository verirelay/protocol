package veriprov1

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

type envelopeSignatureGolden struct {
	IdentitySeed      string       `json:"identity_private_key_seed_base64url"`
	IdentityPublicKey string       `json:"identity_public_key_base64url"`
	Envelope          HPKEEnvelope `json:"envelope"`
	MessageHex        string       `json:"message_hex"`
}

func readEnvelopeSignatureGolden(t *testing.T) (envelopeSignatureGolden, ed25519.PrivateKey) {
	t.Helper()
	data, err := os.ReadFile("testdata/envelope_signature_golden.json")
	if err != nil {
		t.Fatal(err)
	}
	var golden envelopeSignatureGolden
	if err := json.Unmarshal(data, &golden); err != nil {
		t.Fatal(err)
	}
	seed, err := DecodeBase64URL(golden.IdentitySeed, "seed", ed25519.SeedSize)
	if err != nil {
		t.Fatal(err)
	}
	return golden, ed25519.NewKeyFromSeed(seed)
}

func TestEnvelopeSignatureGoldenVector(t *testing.T) {
	golden, priv := readEnvelopeSignatureGolden(t)
	pub := priv.Public().(ed25519.PublicKey)
	if EncodeBase64URL(pub) != golden.IdentityPublicKey {
		t.Fatalf("public key = %s, want %s", EncodeBase64URL(pub), golden.IdentityPublicKey)
	}
	message, err := golden.Envelope.signatureMessage()
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(message); got != golden.MessageHex {
		t.Fatalf("message = %s, want %s", got, golden.MessageHex)
	}
	unsigned := golden.Envelope
	unsigned.Signature = ""
	if err := SignEnvelope(priv, &unsigned); err != nil {
		t.Fatal(err)
	}
	if unsigned.Signature != golden.Envelope.Signature {
		t.Fatalf("signature = %s, want %s", unsigned.Signature, golden.Envelope.Signature)
	}
	if err := VerifyEnvelopeSignature(pub, golden.Envelope); err != nil {
		t.Fatal(err)
	}
	if err := (ProvisionResponse{Envelope: golden.Envelope}).Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyEnvelopeSignatureRejectsTampering(t *testing.T) {
	golden, priv := readEnvelopeSignatureGolden(t)
	pub := priv.Public().(ed25519.PublicKey)
	otherPub := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	if err := VerifyEnvelopeSignature(otherPub, golden.Envelope); err == nil {
		t.Fatal("verified under another identity key")
	}
	if err := VerifyEnvelopeSignature(pub[:31], golden.Envelope); err == nil {
		t.Fatal("accepted a short identity key")
	}
	otherChallenge := EncodeBase64URL([]byte("0123456789abcdef"))
	for name, mutate := range map[string]func(*HPKEEnvelope){
		"challenge_id": func(e *HPKEEnvelope) { e.ChallengeID, e.AAD.ChallengeID = otherChallenge, otherChallenge },
		"enc":          func(e *HPKEEnvelope) { e.Enc = EncodeBase64URL(make([]byte, X25519PublicKeySize)) },
		"ciphertext":   func(e *HPKEEnvelope) { e.Ciphertext = e.Ciphertext[:len(e.Ciphertext)-2] },
		"signature":    func(e *HPKEEnvelope) { e.Signature = EncodeBase64URL(make([]byte, ed25519.SignatureSize)) },
		"no signature": func(e *HPKEEnvelope) { e.Signature = "" },
		"short signature": func(e *HPKEEnvelope) {
			e.Signature = e.Signature[:len(e.Signature)-3]
		},
		"padded signature": func(e *HPKEEnvelope) { e.Signature += "==" },
		"version":          func(e *HPKEEnvelope) { e.Version = "veriprov/2" },
		"aad mismatch":     func(e *HPKEEnvelope) { e.AAD.ChallengeID = otherChallenge },
	} {
		envelope := golden.Envelope
		mutate(&envelope)
		if err := VerifyEnvelopeSignature(pub, envelope); err == nil {
			t.Errorf("%s: verified", name)
		}
	}
}

func TestSignEnvelopeRequiresValidInput(t *testing.T) {
	golden, priv := readEnvelopeSignatureGolden(t)
	envelope := golden.Envelope
	if err := SignEnvelope(priv.Seed(), &envelope); err == nil {
		t.Fatal("accepted a seed as private key")
	}
	envelope.Enc = "short"
	if err := SignEnvelope(priv, &envelope); err == nil {
		t.Fatal("signed an invalid envelope")
	}
}

func TestProvisionResponseValidateRequiresSignature(t *testing.T) {
	golden, _ := readEnvelopeSignatureGolden(t)
	for name, signature := range map[string]string{
		"missing": "",
		"short":   EncodeBase64URL(make([]byte, ed25519.SignatureSize-1)),
		"padded":  golden.Envelope.Signature + "==",
	} {
		envelope := golden.Envelope
		envelope.Signature = signature
		if err := (ProvisionResponse{Envelope: envelope}).Validate(); err == nil || !strings.Contains(err.Error(), "signature") {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func TestProvisionRequestValidate(t *testing.T) {
	valid := ProvisionRequest{
		ChallengeID:           EncodeBase64URL(make([]byte, MinimumChallengeIDSize)),
		ProvisioningPublicKey: EncodeBase64URL(make([]byte, X25519PublicKeySize)),
		AttestationReport:     EncodeBase64URL(make([]byte, AttestationReportSize)),
	}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*ProvisionRequest){
		"short challenge":  func(r *ProvisionRequest) { r.ChallengeID = EncodeBase64URL(make([]byte, MinimumChallengeIDSize-1)) },
		"short public key": func(r *ProvisionRequest) { r.ProvisioningPublicKey = EncodeBase64URL(make([]byte, 31)) },
		"short report": func(r *ProvisionRequest) {
			r.AttestationReport = EncodeBase64URL(make([]byte, AttestationReportSize-1))
		},
		"long report": func(r *ProvisionRequest) {
			r.AttestationReport = EncodeBase64URL(make([]byte, AttestationReportSize+1))
		},
		"missing report": func(r *ProvisionRequest) { r.AttestationReport = "" },
	} {
		request := valid
		mutate(&request)
		if err := request.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
