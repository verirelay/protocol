package avr1

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

type rawCaptureGolden struct {
	Key          string     `json:"key_base64url"`
	StoreID      string     `json:"store_id"`
	RequestBody  string     `json:"request_body_base64url"`
	ResponseBody string     `json:"response_body_base64url"`
	Plaintext    string     `json:"plaintext"`
	AAD          string     `json:"aad"`
	Capture      RawCapture `json:"capture"`
}

type rawCaptureVector struct {
	key, request, response, nonce []byte
	storeID                       string
	capture                       RawCapture
	golden                        rawCaptureGolden
}

func readRawCaptureGolden(t *testing.T) rawCaptureVector {
	t.Helper()
	data, err := os.ReadFile("testdata/raw_capture_golden.json")
	if err != nil {
		t.Fatal(err)
	}
	var golden rawCaptureGolden
	if err := json.Unmarshal(data, &golden); err != nil {
		t.Fatal(err)
	}
	vector := rawCaptureVector{storeID: golden.StoreID, capture: golden.Capture, golden: golden}
	for _, field := range []struct {
		dst   *[]byte
		value string
	}{
		{&vector.key, golden.Key},
		{&vector.request, golden.RequestBody},
		{&vector.response, golden.ResponseBody},
		{&vector.nonce, golden.Capture.Nonce},
	} {
		if *field.dst, err = DecodeBase64URL(field.value); err != nil {
			t.Fatal(err)
		}
	}
	return vector
}

func TestRawCaptureGoldenVector(t *testing.T) {
	v := readRawCaptureGolden(t)
	request, response, err := OpenRawCapture(v.key, v.storeID, v.capture)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(request, v.request) || !bytes.Equal(response, v.response) {
		t.Fatalf("opened %q, %q", request, response)
	}
	sealed, err := sealRawCapture(v.key, v.nonce, v.storeID, v.request, v.response)
	if err != nil {
		t.Fatal(err)
	}
	if sealed != v.capture {
		t.Fatalf("sealed %+v, want %+v", sealed, v.capture)
	}
	plaintext := mustMarshal(t, RawCapturePlaintext{Version: RawCapturePlaintextVersion, RequestBody: v.golden.RequestBody, ResponseBody: v.golden.ResponseBody})
	if string(plaintext) != v.golden.Plaintext || string(rawCaptureAAD(v.storeID)) != v.golden.AAD {
		t.Fatalf("plaintext %s, aad %s", plaintext, rawCaptureAAD(v.storeID))
	}
}

func TestSealRawCaptureRoundTrip(t *testing.T) {
	v := readRawCaptureGolden(t)
	for _, bodies := range [][2][]byte{{v.request, v.response}, {nil, nil}, {[]byte{0, 0xff}, []byte("\n")}} {
		capture, err := SealRawCapture(v.key, v.storeID, bodies[0], bodies[1])
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := DecodeRawCapture(mustMarshal(t, capture))
		if err != nil || decoded != capture {
			t.Fatalf("decoded %+v, %v", decoded, err)
		}
		request, response, err := OpenRawCapture(v.key, v.storeID, decoded)
		if err != nil || !bytes.Equal(request, bodies[0]) || !bytes.Equal(response, bodies[1]) {
			t.Fatalf("opened %q, %q, %v", request, response, err)
		}
	}
	first, _ := SealRawCapture(v.key, v.storeID, v.request, v.response)
	second, _ := SealRawCapture(v.key, v.storeID, v.request, v.response)
	if first.Nonce == second.Nonce {
		t.Fatal("SealRawCapture reused a nonce")
	}
}

func TestOpenRawCaptureRejects(t *testing.T) {
	v := readRawCaptureGolden(t)
	otherKey := bytes.Clone(v.key)
	otherKey[0] ^= 1
	mutated := func(mutate func(*RawCapture)) RawCapture {
		capture := v.capture
		mutate(&capture)
		return capture
	}
	for name, tc := range map[string]struct {
		key     []byte
		storeID string
		capture RawCapture
	}{
		"wrong key":      {otherKey, v.storeID, v.capture},
		"short key":      {v.key[:16], v.storeID, v.capture},
		"wrong store_id": {v.key, v.storeID + "x", v.capture},
		"empty store_id": {v.key, "", v.capture},
		"old version":    {v.key, v.storeID, mutated(func(c *RawCapture) { c.Version = "verirelay.raw_store.v1" })},
		"algorithm":      {v.key, v.storeID, mutated(func(c *RawCapture) { c.Algorithm = "AES-128-GCM" })},
		"short nonce":    {v.key, v.storeID, mutated(func(c *RawCapture) { c.Nonce = c.Nonce[:8] })},
		"padded nonce":   {v.key, v.storeID, mutated(func(c *RawCapture) { c.Nonce += "=" })},
		"ciphertext":     {v.key, v.storeID, mutated(func(c *RawCapture) { c.Ciphertext = "A" + c.Ciphertext[1:] })},
		"std base64":     {v.key, v.storeID, mutated(func(c *RawCapture) { c.Ciphertext = strings.ReplaceAll(c.Ciphertext, "_", "/") })},
		"truncated":      {v.key, v.storeID, mutated(func(c *RawCapture) { c.Ciphertext = c.Ciphertext[:len(c.Ciphertext)-4] })},
	} {
		if request, response, err := OpenRawCapture(tc.key, tc.storeID, tc.capture); err == nil {
			t.Errorf("%s: opened %q, %q", name, request, response)
		}
	}
}

func TestDecodeRawCapture(t *testing.T) {
	v := readRawCaptureGolden(t)
	data := strings.Replace(string(mustMarshal(t, v.capture)), `"algorithm"`, `"future":1,"algorithm"`, 1)
	if capture, err := DecodeRawCapture([]byte(data)); err != nil || capture != v.capture {
		t.Fatalf("unknown field: %+v, %v", capture, err)
	}
	for _, data := range []string{
		strings.Replace(data, `"future":1`, `"nonce":"x"`, 1),
		`{"Version":"verirelay-raw-capture/1"}`,
		`{"schema":"verirelay.raw_store.v1"}` + "{}",
		`[]`,
	} {
		if _, err := DecodeRawCapture([]byte(data)); err == nil {
			t.Errorf("accepted %s", data)
		}
	}
}
