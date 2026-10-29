package avr1

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func testReceiptSignerV1(t *testing.T) *ReceiptSignerV1 {
	t.Helper()
	signer, err := NewReceiptSignerV1(ed25519.NewKeyFromSeed([]byte("0123456789abcdef0123456789abcdef")))
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func testUnsignedReceiptV1() SignedReceiptV1 {
	return SignedReceiptV1{
		RequestID:          "req_01HYW7WZ7JQ7J7Y4ZK6KJ9Q2R3",
		Timestamp:          "2026-07-11T07:00:00Z",
		Method:             "POST",
		UpstreamAuthority:  "api.example.com",
		UpstreamPath:       "/v1/chat/completions?version=1",
		RequestBodySHA256:  SHA256Hex([]byte(`{"model":"test","messages":[{"role":"user","content":"ping"}]}`)),
		ResponseBodySHA256: SHA256Hex([]byte(`{"ok":true}`)),
		ResponseStatus:     200,
		UpstreamTLS:        UpstreamTLSIdentityV1{SNI: "api.example.com", SPKISHA256: SHA256Hex([]byte("spki"))},
	}
}

func testReceiptFactsV1() ReceiptFactsV1 {
	return ReceiptFactsV1{
		RequestID:          "req_01HYW7WZ7JQ7J7Y4ZK6KJ9Q2R3",
		Timestamp:          "2026-07-11T07:00:00Z",
		Method:             "POST",
		UpstreamAuthority:  "api.example.com",
		UpstreamPath:       "/v1/chat/completions?version=1",
		SNI:                "api.example.com",
		UpstreamSPKISHA256: SHA256Hex([]byte("spki")),
		RequestBodySHA256:  SHA256Hex([]byte(`{"model":"test","messages":[{"role":"user","content":"ping"}]}`)),
		ResponseBodySHA256: SHA256Hex([]byte(`{"ok":true}`)),
		ResponseStatus:     200,
	}
}

func testSignedReceiptV1(t *testing.T) SignedReceiptV1 {
	t.Helper()
	receipt := testUnsignedReceiptV1()
	if err := testReceiptSignerV1(t).Sign(&receipt); err != nil {
		t.Fatal(err)
	}
	return receipt
}

func TestSignedReceiptV1RoundTrip(t *testing.T) {
	signer := testReceiptSignerV1(t)
	receipt := testUnsignedReceiptV1()
	if err := signer.Sign(&receipt); err != nil {
		t.Fatal(err)
	}
	if receipt.Version != AVRVersion || receipt.Canonicalization != avrCanonicalization || receipt.SignatureAlgorithm != AVRSignatureAlgorithm || receipt.HashAlgorithm != avrHashAlgorithm {
		t.Fatalf("algorithm identifiers not fixed: %+v", receipt)
	}
	if receipt.ServicePublicKey != signer.PublicKeyBase64URL() || receipt.KeyID != signer.KeyID() {
		t.Fatalf("key metadata mismatch: %+v", receipt)
	}
	if err := VerifySignedReceiptV1(receipt); err != nil {
		t.Fatalf("signature did not verify: %v", err)
	}
	data, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := VerifySignedReceiptJSONV1(data)
	if err != nil {
		t.Fatalf("json did not verify: %v", err)
	}
	if again := mustMarshal(t, verified); !bytes.Equal(again, data) {
		t.Fatalf("verified receipt = %s, want %s", again, data)
	}
}

func TestBuildSignedReceiptV1StableForSameFacts(t *testing.T) {
	signer := testReceiptSignerV1(t)
	facts := testReceiptFactsV1()

	first, err := BuildSignedReceiptV1(facts, signer)
	if err != nil {
		t.Fatal(err)
	}
	second, err := BuildSignedReceiptV1(facts, signer)
	if err != nil {
		t.Fatal(err)
	}
	firstHash, firstPayload, err := canonicalSignedReceiptPayload(first)
	if err != nil {
		t.Fatal(err)
	}
	secondHash, secondPayload, err := canonicalSignedReceiptPayload(second)
	if err != nil {
		t.Fatal(err)
	}
	if firstHash != secondHash || string(firstPayload) != string(secondPayload) {
		t.Fatalf("canonical payload changed:\nfirst:  %s\nsecond: %s", firstPayload, secondPayload)
	}
	if first.Signature == nil || second.Signature == nil || *first.Signature != *second.Signature {
		t.Fatalf("signature changed for same facts:\nfirst:  %+v\nsecond: %+v", first.Signature, second.Signature)
	}
	if err := VerifySignedReceiptV1(first); err != nil {
		t.Fatalf("built receipt did not verify: %v", err)
	}
}

func TestBuildSignedReceiptV1RequiresSPKI(t *testing.T) {
	facts := testReceiptFactsV1()
	facts.UpstreamSPKISHA256 = ""
	if _, err := BuildSignedReceiptV1(facts, testReceiptSignerV1(t)); err == nil || !strings.Contains(err.Error(), "upstream_tls.spki_sha256") {
		t.Fatalf("receipt without SPKI err = %v", err)
	}
	if _, err := BuildSignedReceiptV1(testReceiptFactsV1(), nil); err == nil {
		t.Fatal("built a receipt without a signer")
	}
}

func TestSignedReceiptV1JSONFieldOrderDoesNotAffectVerification(t *testing.T) {
	receipt := testSignedReceiptV1(t)
	ordered, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	reordered := []byte(`{"signature":{"value":"` + receipt.Signature.Value + `","payload_sha256":"` + receipt.Signature.PayloadSHA256 + `"},"upstream_tls":{"spki_sha256":"` + receipt.UpstreamTLS.SPKISHA256 + `","sni":"api.example.com"},"upstream_path":"/v1/chat/completions?version=1","upstream_authority":"api.example.com","timestamp":"2026-07-11T07:00:00Z","signature_algorithm":"ed25519","service_public_key":"` + receipt.ServicePublicKey + `","response_status":200,"response_body_sha256":"` + receipt.ResponseBodySHA256 + `","request_id":"req_01HYW7WZ7JQ7J7Y4ZK6KJ9Q2R3","request_body_sha256":"` + receipt.RequestBodySHA256 + `","method":"POST","key_id":"` + receipt.KeyID + `","hash_algorithm":"sha256","canonicalization":"jcs-rfc8785","version":"avr/1"}`)
	for name, data := range map[string][]byte{"ordered": ordered, "reordered": reordered} {
		if _, err := VerifySignedReceiptJSONV1(data); err != nil {
			t.Fatalf("%s json did not verify: %v", name, err)
		}
	}
}

func TestSignedReceiptV1RejectsTamperedSignedFields(t *testing.T) {
	base := testSignedReceiptV1(t)
	for _, tc := range []struct {
		name   string
		mutate func(*SignedReceiptV1)
	}{
		{name: "method", mutate: func(r *SignedReceiptV1) { r.Method = "GET" }},
		{name: "authority", mutate: func(r *SignedReceiptV1) { r.UpstreamAuthority = "api.other.example" }},
		{name: "path", mutate: func(r *SignedReceiptV1) { r.UpstreamPath = "/v1/messages" }},
		{name: "request body", mutate: func(r *SignedReceiptV1) { r.RequestBodySHA256 = SHA256Hex([]byte("tampered-request")) }},
		{name: "response body", mutate: func(r *SignedReceiptV1) { r.ResponseBodySHA256 = SHA256Hex([]byte("tampered-response")) }},
		{name: "status", mutate: func(r *SignedReceiptV1) { r.ResponseStatus = 500 }},
		{name: "tls sni", mutate: func(r *SignedReceiptV1) { r.UpstreamTLS.SNI = "evil.example" }},
		{name: "tls spki", mutate: func(r *SignedReceiptV1) { r.UpstreamTLS.SPKISHA256 = SHA256Hex([]byte("other-spki")) }},
		{name: "public key", mutate: func(r *SignedReceiptV1) {
			other, err := NewReceiptSignerV1(ed25519.NewKeyFromSeed([]byte("abcdef0123456789abcdef0123456789")))
			if err != nil {
				t.Fatal(err)
			}
			r.ServicePublicKey = other.PublicKeyBase64URL()
		}},
		{name: "key id", mutate: func(r *SignedReceiptV1) { r.KeyID = "0000000000000000" }},
		{name: "missing signature", mutate: func(r *SignedReceiptV1) { r.Signature = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			receipt := base
			signature := *base.Signature
			receipt.Signature = &signature
			tc.mutate(&receipt)
			if err := VerifySignedReceiptV1(receipt); err == nil {
				t.Fatalf("tampered receipt verified")
			}
		})
	}
}

func TestSignedReceiptV1RejectsUnsupportedVersionAndMissingRequiredFields(t *testing.T) {
	receipt := testSignedReceiptV1(t)
	receipt.Version = "avr/2"
	if err := VerifySignedReceiptV1(receipt); !errors.Is(err, errUnsupportedAVRVersion) {
		t.Fatalf("err = %v, want unsupported", err)
	}

	missing := testUnsignedReceiptV1()
	missing.Method = ""
	if err := testReceiptSignerV1(t).Sign(&missing); err == nil || !strings.Contains(err.Error(), "missing required field") {
		t.Fatalf("missing required field err = %v", err)
	}
}

func TestSignedReceiptV1RejectsNonUTCTimestampAndDisclosureFields(t *testing.T) {
	nonUTC := testUnsignedReceiptV1()
	nonUTC.Timestamp = "2026-07-11T15:00:00+08:00"
	if err := testReceiptSignerV1(t).Sign(&nonUTC); err == nil || !strings.Contains(err.Error(), "timestamp") {
		t.Fatalf("non-UTC timestamp err = %v", err)
	}

	encoded, err := json.Marshal(testSignedReceiptV1(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"source", "launch", "launch_profile", "launch_observed", "manifest", "api_version", "challenge"} {
		t.Run(field, func(t *testing.T) {
			var raw map[string]any
			if err := json.Unmarshal(encoded, &raw); err != nil {
				t.Fatal(err)
			}
			raw[field] = map[string]any{}
			withDisclosure, err := json.Marshal(raw)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := VerifySignedReceiptJSONV1(withDisclosure); err == nil || !strings.Contains(err.Error(), "unknown JSON field") {
				t.Fatalf("disclosure field error = %v", err)
			}
		})
	}
}
