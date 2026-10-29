package avr1

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func setRaw(field string, value any) func(map[string]any) {
	return func(raw map[string]any) { raw[field] = value }
}

func deleteRaw(field string) func(map[string]any) {
	return func(raw map[string]any) { delete(raw, field) }
}

func setNested(object, field string, value any) func(map[string]any) {
	return func(raw map[string]any) { raw[object].(map[string]any)[field] = value }
}

func testRawReceiptV1(t *testing.T) map[string]any {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(mustMarshal(t, testSignedReceiptV1(t))))
	decoder.UseNumber()
	var raw map[string]any
	if err := decoder.Decode(&raw); err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestVerifySignedReceiptJSONV1RejectsEachRule(t *testing.T) {
	type rawCase struct {
		name   string
		mutate func(map[string]any)
		detail string
	}
	cases := []rawCase{
		{"unknown field", setRaw("extra", "x"), `unknown JSON field "extra"`},
		{"old api_version", setRaw("api_version", "avr/1"), `unknown JSON field "api_version"`},
		{"unknown upstream_tls field", setNested("upstream_tls", "extra", "x"), `unknown JSON field "upstream_tls.extra"`},
		{"unknown signature field", setNested("signature", "extra", "x"), `unknown JSON field "signature.extra"`},
		{"null signature", setRaw("signature", nil), `optional JSON field "signature" must be omitted`},
		{"missing signature", deleteRaw("signature"), "missing signature"},
		{"version missing", deleteRaw("version"), "invalid signed receipt: version"},
		{"version invalid", setRaw("version", "v1"), "invalid signed receipt: version"},
		{"response_status string", setRaw("response_status", "200"), "cannot unmarshal"},
		{"response_status fraction", setRaw("response_status", json.Number("200.5")), "cannot unmarshal"},
		{"response_status exponent", setRaw("response_status", json.Number("2e2")), "cannot unmarshal"},
		{"response_status below 100", setRaw("response_status", json.Number("99")), "response_status must be from 100 to 599"},
		{"response_status above 599", setRaw("response_status", json.Number("600")), "response_status must be from 100 to 599"},
		{"upstream_tls not object", setRaw("upstream_tls", "x"), "cannot unmarshal"},
		{"sni missing", func(raw map[string]any) { delete(raw["upstream_tls"].(map[string]any), "sni") }, "missing required field"},
		{"spki_sha256 missing", func(raw map[string]any) { delete(raw["upstream_tls"].(map[string]any), "spki_sha256") }, "upstream_tls.spki_sha256"},
		{"spki_sha256 empty", setNested("upstream_tls", "spki_sha256", ""), "upstream_tls.spki_sha256"},
		{"spki_sha256 uppercase", setNested("upstream_tls", "spki_sha256", strings.Repeat("A", 64)), "upstream_tls.spki_sha256"},
		{"request_body_sha256 invalid", setRaw("request_body_sha256", "xyz"), "request_body_sha256"},
		{"response_body_sha256 invalid", setRaw("response_body_sha256", "xyz"), "response_body_sha256"},
		{"service_public_key invalid", setRaw("service_public_key", "!"), "service_public_key"},
		{"service_public_key length", setRaw("service_public_key", "AAAA"), "service_public_key length"},
		{"key_id mismatch", setRaw("key_id", "other"), "key_id"},
		{"timestamp not UTC", setRaw("timestamp", "2026-07-11T15:00:00+08:00"), "timestamp must use UTC Z"},
		{"timestamp invalid", setRaw("timestamp", "notatimeZ"), "timestamp"},
		{"payload hash mismatch", setNested("signature", "payload_sha256", strings.Repeat("0", 64)), "payload hash mismatch"},
		{"signature value padded", func(raw map[string]any) {
			signature := raw["signature"].(map[string]any)
			signature["value"] = signature["value"].(string) + "=="
		}, "signature.value"},
		{"signature value short", setNested("signature", "value", "AAAA"), "signature.value length"},
	}
	for _, field := range []string{"canonicalization", "signature_algorithm", "hash_algorithm"} {
		cases = append(cases,
			rawCase{field + " missing", deleteRaw(field), "algorithm identifiers"},
			rawCase{field + " mismatch", setRaw(field, "other"), "algorithm identifiers"},
		)
	}
	for _, field := range []string{"request_id", "method", "upstream_authority", "upstream_path", "key_id"} {
		cases = append(cases,
			rawCase{field + " missing", deleteRaw(field), "missing required field"},
			rawCase{field + " empty", setRaw(field, ""), "missing required field"},
			rawCase{field + " not string", setRaw(field, json.Number("1")), "cannot unmarshal"},
		)
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			raw := testRawReceiptV1(t)
			c.mutate(raw)
			_, err := VerifySignedReceiptJSONV1(mustMarshal(t, raw))
			if err == nil || !strings.Contains(err.Error(), c.detail) {
				t.Fatalf("err = %v, want %q", err, c.detail)
			}
			if !errors.Is(err, errInvalidSignedReceipt) && !errors.Is(err, errInvalidSignature) {
				t.Fatalf("err = %v does not wrap a receipt sentinel", err)
			}
		})
	}
	raw := testRawReceiptV1(t)
	raw["version"] = "avr/2"
	if _, err := VerifySignedReceiptJSONV1(mustMarshal(t, raw)); !errors.Is(err, errUnsupportedAVRVersion) {
		t.Fatalf("avr/2 err = %v, want unsupported", err)
	}
}

func TestVerifySignedReceiptJSONV1RejectsNonCanonicalBase64URL(t *testing.T) {
	receipt := testSignedReceiptV1(t)
	// The last character of 32-byte and 64-byte base64url values carries
	// padding bits; flipping one keeps the decoded bytes but breaks canonicity.
	for name, mutate := range map[string]func(*SignedReceiptV1){
		"service_public_key": func(r *SignedReceiptV1) { r.ServicePublicKey = flipPaddingBit(r.ServicePublicKey) },
		"signature.value":    func(r *SignedReceiptV1) { r.Signature.Value = flipPaddingBit(r.Signature.Value) },
	} {
		mutated := receipt
		signature := *receipt.Signature
		mutated.Signature = &signature
		mutate(&mutated)
		if _, err := VerifySignedReceiptJSONV1(mustMarshal(t, mutated)); err == nil || !strings.Contains(err.Error(), name) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

// flipPaddingBit changes the final character of an unpadded base64url value
// so that it decodes to the same bytes with a non-zero padding bit.
func flipPaddingBit(value string) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	last := strings.IndexByte(alphabet, value[len(value)-1])
	return value[:len(value)-1] + string(alphabet[last^1])
}

func TestDecodeSignedReceiptV1RejectsMalformedJSON(t *testing.T) {
	data := string(mustMarshal(t, testSignedReceiptV1(t)))
	for name, input := range map[string]string{
		"duplicate key":         strings.Replace(data, `"method":"POST"`, `"method":"POST","method":"POST"`, 1),
		"duplicate nested key":  strings.Replace(data, `"sni":"api.example.com"`, `"sni":"api.example.com","sni":"api.example.com"`, 1),
		"case-folded key":       strings.Replace(data, `"method"`, `"Method"`, 1),
		"case-folded duplicate": strings.Replace(data, `"method":"POST"`, `"method":"POST","METHOD":"GET"`, 1),
		"trailing value":        data + "{}",
		"array":                 "[" + data + "]",
		"null":                  "null",
	} {
		if _, err := DecodeSignedReceiptV1([]byte(input)); err == nil {
			t.Errorf("%s: accepted", name)
		} else if !errors.Is(err, errInvalidSignedReceipt) {
			t.Errorf("%s: err = %v does not wrap the receipt sentinel", name, err)
		}
	}
}

func TestSignedReceiptV1ResponseStatusBounds(t *testing.T) {
	for _, status := range []int{100, 599} {
		receipt := testUnsignedReceiptV1()
		receipt.ResponseStatus = status
		if err := testReceiptSignerV1(t).Sign(&receipt); err != nil {
			t.Fatalf("status %d: %v", status, err)
		}
		if _, err := VerifySignedReceiptJSONV1(mustMarshal(t, receipt)); err != nil {
			t.Fatalf("status %d: %v", status, err)
		}
	}
}

func mustMarshal(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
