package avr1

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/verirelay/protocol/guest"
)

// Offsets of REPORT_DATA and HOST_DATA in a raw AMD SEV-SNP attestation report.
const (
	reportDataOffset = 0x50
	hostDataOffset   = 0xc0
)

func TestAttestationResponseGoldenVectors(t *testing.T) {
	var withoutBootstrap AttestationResponse
	for _, tc := range []struct {
		name      string
		bootstrap bool
	}{
		{name: "without_bootstrap"},
		{name: "with_bootstrap", bootstrap: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := os.ReadFile("testdata/avr1_attestation_" + tc.name + ".json")
			if err != nil {
				t.Fatal(err)
			}
			response, err := DecodeAttestationResponse(raw)
			if err != nil {
				t.Fatal(err)
			}
			if response.Version != AVRVersion || response.TEEType != AttestationTEETypeSEVSNP || response.Evidence.Format != AttestationEvidenceFormat {
				t.Fatalf("unexpected attestation metadata: %+v", response)
			}
			report, err := DecodeBase64URL(response.Evidence.Report)
			if err != nil || len(report) != AttestationReportSize {
				t.Fatalf("evidence.report = %d bytes, %v", len(report), err)
			}
			endorsements := response.Endorsements
			if endorsements.Format != AttestationEndorsementsFormat || endorsements.Encoding != AttestationEndorsementsEncoding || endorsements.VLEK != "" {
				t.Fatalf("unexpected endorsements: %+v", endorsements)
			}
			for _, der := range []string{endorsements.VCEK, endorsements.ASK, endorsements.ARK} {
				if decoded, err := DecodeBase64URL(der); err != nil || len(decoded) == 0 {
					t.Fatalf("certificate is not base64url DER: %v", err)
				}
			}
			publicKey, err := DecodeEd25519PublicKeyBase64URL(response.ReceiptSigningPublicKey)
			if err != nil {
				t.Fatal(err)
			}
			nonce, err := DecodeNonceBase64URL(response.Nonce)
			if err != nil {
				t.Fatal(err)
			}
			reportData, err := ReportDataAVR1(publicKey, nonce)
			if err != nil {
				t.Fatal(err)
			}
			binding := response.KeyBinding
			if binding.Rule != AttestationBindingRuleV1 || binding.ProtocolVersion != AVRVersion ||
				binding.SignatureAlgorithm != AVRSignatureAlgorithm || binding.ReportDataEncoding != AttestationReportDataEncoding ||
				binding.PublicKeyEncoding != AttestationPublicKeyEncoding || binding.NonceEncoding != AttestationNonceEncoding ||
				binding.ReportDataSHA512 != hex.EncodeToString(reportData[:]) || response.Evidence.ReportData != binding.ReportDataSHA512 ||
				!bytes.Equal(report[reportDataOffset:reportDataOffset+64], reportData[:]) || response.KeyID != ReceiptKeyID(publicKey) {
				t.Fatalf("unexpected key binding: %+v", binding)
			}
			if (response.Bootstrap != "") != tc.bootstrap {
				t.Fatalf("bootstrap = %q, want present: %v", response.Bootstrap, tc.bootstrap)
			}
			var encoded bytes.Buffer
			if err := json.NewEncoder(&encoded).Encode(response); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(encoded.Bytes(), raw) {
				t.Fatalf("JSON bytes changed:\n got: %s\nwant: %s", encoded.Bytes(), raw)
			}
			if !tc.bootstrap {
				withoutBootstrap = response
				return
			}
			bootstrap, err := DecodeBase64URL(response.Bootstrap)
			if err != nil {
				t.Fatal(err)
			}
			hostData := guest.HostData(bootstrap)
			if !bytes.Equal(report[hostDataOffset:hostDataOffset+sha256.Size], hostData[:]) {
				t.Fatal("report HOST_DATA is not the SHA-256 of bootstrap")
			}
			decoded, err := guest.DecodeBootstrap(bootstrap)
			if err != nil {
				t.Fatal(err)
			}
			if err := decoded.Validate(); err != nil {
				t.Fatal(err)
			}
			response.Bootstrap = ""
			if !reflect.DeepEqual(response, withoutBootstrap) {
				t.Fatal("golden cases differ beyond bootstrap")
			}
		})
	}
}

func TestDecodeAttestationResponseIsLenient(t *testing.T) {
	raw, err := os.ReadFile("testdata/avr1_attestation_with_bootstrap.json")
	if err != nil {
		t.Fatal(err)
	}
	want, err := DecodeAttestationResponse(raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		"", "evidence", "endorsements", "key_binding", "source", "source.verirelay",
		"source.veriforge", "launch_profile",
	} {
		t.Run("unknown/"+path, func(t *testing.T) {
			got, err := DecodeAttestationResponse(withNestedKey(t, raw, path, "future", `{"x":[1]}`))
			if err != nil {
				t.Fatalf("unknown field rejected: %v", err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("unknown field changed the response: %+v", got)
			}
		})
	}
	for path, key := range map[string]string{"": "Version", "evidence": "Report", "key_binding": "RULE", "launch_profile": "Kernel_Append"} {
		if _, err := DecodeAttestationResponse(withNestedKey(t, raw, path, key, `"x"`)); err == nil {
			t.Errorf("case-folded key %q in %q accepted", key, path)
		}
	}
	for name, data := range map[string]string{
		"duplicate top-level": strings.Replace(string(raw), `"tee_type"`, `"tee_type":"sev-snp","tee_type"`, 1),
		"duplicate nested":    strings.Replace(string(raw), `"rule"`, `"rule":"x","rule"`, 1),
		"duplicate in source": strings.Replace(string(raw), `"commit"`, `"commit":"x","commit"`, 1),
	} {
		if _, err := DecodeAttestationResponse([]byte(data)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// withNestedKey returns raw with key: value added to the object at the dotted
// path ("" is the top level).
func withNestedKey(t *testing.T, raw []byte, path, key, value string) []byte {
	t.Helper()
	var object map[string]any
	if err := json.Unmarshal(raw, &object); err != nil {
		t.Fatal(err)
	}
	nested := object
	if path != "" {
		for field := range strings.SplitSeq(path, ".") {
			nested = nested[field].(map[string]any)
		}
	}
	nested[key] = json.RawMessage(value)
	return mustMarshal(t, object)
}

func TestDecodeAttestationResponseRejectsInvalidJSON(t *testing.T) {
	for _, data := range []string{
		"", " \n\t", "null", "[]", `"response"`, "1", "true", "{",
		`{} {}`, `{} null`, `{} false`, `{} garbage`,
		`{"evidence":{"format":1}}`, `{"endorsements":[]}`,
		`{"launch_profile":{"kernel_hashes":"true"}}`, `{"bootstrap":false}`,
	} {
		t.Run(data, func(t *testing.T) {
			response, err := DecodeAttestationResponse([]byte(data))
			if err == nil {
				t.Fatal("invalid response accepted")
			}
			if !reflect.DeepEqual(response, AttestationResponse{}) {
				t.Fatalf("partial response returned on error: %+v", response)
			}
		})
	}
}

func TestDecodeAttestationResponseOnlyChecksJSONShape(t *testing.T) {
	for _, data := range []string{
		"{} \n\t", `{"bootstrap":null}`, `{"version":"avr/future"}`, `{"provisioning":{}}`,
		`{"evidence":{"format":"unknown","report":"not-base64"}}`,
	} {
		if _, err := DecodeAttestationResponse([]byte(data)); err != nil {
			t.Fatalf("shape-only decoding rejected %q: %v", data, err)
		}
	}
}

func TestAttestationResponseOptionalFields(t *testing.T) {
	response := AttestationResponse{
		Evidence:     AttestationEvidence{Format: AttestationEvidenceFormat, Report: "report", ReportData: "report-data"},
		Endorsements: AttestationEndorsements{VLEK: "vlek"},
	}
	data := mustMarshal(t, response)
	var object map[string]json.RawMessage
	if err := json.Unmarshal(data, &object); err != nil {
		t.Fatal(err)
	}
	if _, ok := object["bootstrap"]; ok {
		t.Fatal("empty bootstrap was not omitted")
	}
	if len(object) != 10 {
		t.Fatalf("unexpected top-level fields: %s", data)
	}
	if string(object["endorsements"]) != `{"format":"","encoding":"","vlek":"vlek","ask":"","ark":""}` {
		t.Fatalf("unexpected optional endorsement fields: %s", object["endorsements"])
	}
	decoded, err := DecodeAttestationResponse(data)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decoded, response) {
		t.Fatalf("optional fields did not round trip: %+v", decoded)
	}
}
