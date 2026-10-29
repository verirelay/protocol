package avr1

import (
	"encoding/json"
	"errors"
	"os"
	"testing"
)

type signedReceiptFixture struct {
	InputJSON            json.RawMessage `json:"input_json"`
	ReorderedJSON        json.RawMessage `json:"reordered_json"`
	CanonicalPayload     string          `json:"canonical_payload"`
	PayloadSHA256        string          `json:"payload_sha256"`
	ServicePublicKey     string          `json:"service_public_key"`
	KeyID                string          `json:"key_id"`
	Signature            string          `json:"signature"`
	ExpectedVerification string          `json:"expected_verification"`
	NegativeCases        []struct {
		Name     string `json:"name"`
		Field    string `json:"field"`
		Value    string `json:"value"`
		Expected string `json:"expected"`
	} `json:"negative_cases"`
}

func readSignedReceiptFixture(t *testing.T) signedReceiptFixture {
	t.Helper()
	data, err := os.ReadFile("testdata/avr1_signed_receipt_golden.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture signedReceiptFixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func TestSignedReceiptV1GoldenVector(t *testing.T) {
	fixture := readSignedReceiptFixture(t)
	if fixture.ExpectedVerification != "valid" {
		t.Fatalf("fixture expectation = %s", fixture.ExpectedVerification)
	}
	receipt, err := VerifySignedReceiptJSONV1(fixture.InputJSON)
	if err != nil {
		t.Fatalf("input json did not verify: %v", err)
	}
	if _, err := VerifySignedReceiptJSONV1(fixture.ReorderedJSON); err != nil {
		t.Fatalf("reordered json did not verify: %v", err)
	}
	payloadHash, payload, err := canonicalSignedReceiptPayload(receipt)
	if err != nil {
		t.Fatal(err)
	}
	if string(payload) != fixture.CanonicalPayload {
		t.Fatalf("canonical payload mismatch:\n got: %s\nwant: %s", payload, fixture.CanonicalPayload)
	}
	if payloadHash != fixture.PayloadSHA256 {
		t.Fatalf("payload hash = %s, want %s", payloadHash, fixture.PayloadSHA256)
	}
	if receipt.ServicePublicKey != fixture.ServicePublicKey || receipt.KeyID != fixture.KeyID || receipt.Signature.Value != fixture.Signature {
		t.Fatalf("fixture signature metadata mismatch: %+v", receipt)
	}
	signed := testUnsignedReceiptV1()
	if err := testReceiptSignerV1(t).Sign(&signed); err != nil {
		t.Fatal(err)
	}
	if got, want := mustMarshal(t, signed), mustMarshal(t, receipt); string(got) != string(want) {
		t.Fatalf("signing the test receipt does not reproduce the fixture:\n got: %s\nwant: %s", got, want)
	}
}

func TestSignedReceiptV1GoldenNegativeCases(t *testing.T) {
	fixture := readSignedReceiptFixture(t)
	if len(fixture.NegativeCases) == 0 {
		t.Fatal("fixture has no negative cases")
	}
	for _, c := range fixture.NegativeCases {
		t.Run(c.Name, func(t *testing.T) {
			var receipt map[string]any
			if err := json.Unmarshal(fixture.InputJSON, &receipt); err != nil {
				t.Fatal(err)
			}
			receipt[c.Field] = c.Value
			_, err := VerifySignedReceiptJSONV1(mustMarshal(t, receipt))
			switch c.Expected {
			case "unsupported":
				if !errors.Is(err, errUnsupportedAVRVersion) {
					t.Fatalf("err = %v, want unsupported", err)
				}
			case "invalid":
				if err == nil || errors.Is(err, errUnsupportedAVRVersion) {
					t.Fatalf("err = %v, want invalid", err)
				}
			default:
				t.Fatalf("unknown expectation %q", c.Expected)
			}
		})
	}
}
