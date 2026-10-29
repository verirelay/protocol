package veriprov1

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

type bindingGolden struct {
	Protocol           string `json:"protocol"`
	NonceBase64URL     string `json:"nonce_base64url"`
	PublicKeyBase64URL string `json:"public_key_base64url"`
	BindingInputHex    string `json:"binding_input_hex"`
	ReportDataHex      string `json:"report_data_sha512_hex"`
}

func TestBindingGoldenVector(t *testing.T) {
	data, err := os.ReadFile("testdata/binding_golden.json")
	if err != nil {
		t.Fatal(err)
	}
	var golden bindingGolden
	if err := json.Unmarshal(data, &golden); err != nil {
		t.Fatal(err)
	}
	if golden.Protocol != ProtocolVersion {
		t.Fatalf("protocol = %q", golden.Protocol)
	}
	nonce, err := DecodeBase64URL(golden.NonceBase64URL, "nonce", NonceSize)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := DecodeBase64URL(golden.PublicKeyBase64URL, "public_key", X25519PublicKeySize)
	if err != nil {
		t.Fatal(err)
	}
	input, err := bindingInput(nonce, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(input); got != golden.BindingInputHex {
		t.Fatalf("binding input = %s, want %s", got, golden.BindingInputHex)
	}
	reportData, err := ReportData(nonce, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(reportData[:]); got != golden.ReportDataHex {
		t.Fatalf("report data = %s, want %s", got, golden.ReportDataHex)
	}
}

func TestBase64URLRejectsNonCanonicalValues(t *testing.T) {
	for _, value := range []string{"AQID=", "AQ+", "AQ/", "%%%", ""} {
		if _, err := DecodeBase64URL(value, "value", -1); err == nil {
			t.Fatalf("accepted %q", value)
		}
	}
}

func TestReportDataChangesWhenBoundInputChanges(t *testing.T) {
	nonce := []byte("0123456789abcdefghijklmnopqrstuv")
	publicKey := []byte("abcdefghijklmnopqrstuvwxyz012345")
	base, err := ReportData(nonce, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	nonce[0] ^= 0xff
	changedNonce, err := ReportData(nonce, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	publicKey[0] ^= 0xff
	changedKey, err := ReportData(nonce, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	if base == changedNonce || changedNonce == changedKey || base == changedKey {
		t.Fatal("changing binding input did not change report data")
	}
}

func TestDecodeJSONIsLenient(t *testing.T) {
	var request ProvisionRequest
	if err := DecodeJSON([]byte(`{"challenge_id":"a","future":{"x":[1]},"aad":{"protocol":"x"}}`), &request); err != nil || request.ChallengeID != "a" {
		t.Fatalf("unknown fields not ignored: %+v, %v", request, err)
	}
	var empty ChallengeRequest
	if err := DecodeJSON([]byte(`{"future":true}`), &empty); err != nil {
		t.Fatalf("challenge request with an unknown field: %v", err)
	}
	for _, input := range []string{
		`{}` + `{}`, `[]`, `null`, ``, `{"value":1,"value":2}`,
		`{"challenge_id":"a","challenge_id":"b"}`,
		`{"future":{"x":1,"x":2}}`,
		`{"Challenge_ID":"a"}`,
		`{"challenge_id":1}`,
	} {
		if err := DecodeJSON([]byte(input), &request); err == nil {
			t.Errorf("accepted %q", input)
		}
	}
}
