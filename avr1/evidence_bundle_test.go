package avr1

import (
	"os"
	"reflect"
	"strings"
	"testing"
)

func testBundleJSON(t *testing.T, attestation string) string {
	t.Helper()
	return `{"version":"avr/1","receipt":` + string(mustMarshal(t, testSignedReceiptV1(t))) + `,"attestation":` + attestation + `}`
}

func TestDecodeReceiptEvidenceBundle(t *testing.T) {
	attestation, err := os.ReadFile("testdata/avr1_attestation_with_bootstrap.json")
	if err != nil {
		t.Fatal(err)
	}
	wantAttestation, err := DecodeAttestationResponse(attestation)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := DecodeReceiptEvidenceBundle([]byte(testBundleJSON(t, string(attestation))))
	if err != nil {
		t.Fatal(err)
	}
	if bundle.Version != AVRVersion || bundle.Attestation == nil || !reflect.DeepEqual(*bundle.Attestation, wantAttestation) {
		t.Fatalf("decoded %+v", bundle)
	}
	if err := VerifySignedReceiptV1(bundle.Receipt); err != nil {
		t.Fatalf("decoded receipt does not verify: %v", err)
	}
	encoded, err := DecodeReceiptEvidenceBundle(mustMarshal(t, bundle))
	if err != nil || !reflect.DeepEqual(encoded, bundle) {
		t.Fatalf("bundle did not round trip: %+v, %v", encoded, err)
	}

	for name, data := range map[string]string{
		"null attestation":   testBundleJSON(t, "null"),
		"absent attestation": strings.Replace(testBundleJSON(t, "null"), `,"attestation":null`, "", 1),
	} {
		bundle, err := DecodeReceiptEvidenceBundle([]byte(data))
		if err != nil || bundle.Attestation != nil {
			t.Fatalf("%s: %+v, %v", name, bundle, err)
		}
	}
	if data := mustMarshal(t, ReceiptEvidenceBundle{Version: AVRVersion, Receipt: testSignedReceiptV1(t)}); !strings.HasSuffix(string(data), `,"attestation":null}`) {
		t.Fatalf("nil attestation not encoded as null: %s", data)
	}
}

func TestDecodeReceiptEvidenceBundleIsLenientOutsideTheReceipt(t *testing.T) {
	attestation := `{"version":"avr/1","future":true,"evidence":{"future":1}}`
	data := strings.Replace(testBundleJSON(t, attestation), `"version":"avr/1","receipt"`, `"version":"avr/1","future":{"x":1},"receipt"`, 1)
	bundle, err := DecodeReceiptEvidenceBundle([]byte(data))
	if err != nil {
		t.Fatal(err)
	}
	if bundle.Attestation == nil || bundle.Attestation.Version != AVRVersion {
		t.Fatalf("attestation = %+v", bundle.Attestation)
	}
}

func TestDecodeReceiptEvidenceBundleRejects(t *testing.T) {
	valid := testBundleJSON(t, "null")
	for name, data := range map[string]string{
		"unknown receipt field":  strings.Replace(valid, `"method":"POST"`, `"method":"POST","extra":1`, 1),
		"unknown upstream_tls":   strings.Replace(valid, `"sni":"api.example.com"`, `"sni":"api.example.com","extra":1`, 1),
		"duplicate receipt key":  strings.Replace(valid, `"method":"POST"`, `"method":"POST","method":"GET"`, 1),
		"duplicate bundle key":   strings.Replace(valid, `"version":"avr/1","receipt"`, `"version":"avr/1","version":"avr/1","receipt"`, 1),
		"duplicate attestation":  strings.Replace(valid, `"attestation":null`, `"attestation":{"tee_type":"a","tee_type":"b"}`, 1),
		"old api_version":        strings.Replace(valid, `{"version":"avr/1","receipt"`, `{"api_version":"avr/1","receipt"`, 1),
		"wrong version":          strings.Replace(valid, `{"version":"avr/1","receipt"`, `{"version":"avr/2","receipt"`, 1),
		"missing receipt":        `{"version":"avr/1","attestation":null}`,
		"null receipt":           `{"version":"avr/1","receipt":null,"attestation":null}`,
		"receipt not object":     `{"version":"avr/1","receipt":[],"attestation":null}`,
		"attestation not object": strings.Replace(valid, `"attestation":null`, `"attestation":[]`, 1),
		"case-folded bundle key": strings.Replace(valid, `"receipt"`, `"Receipt"`, 1),
		"trailing data":          valid + "{}",
		"not an object":          `[]`,
	} {
		if _, err := DecodeReceiptEvidenceBundle([]byte(data)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
