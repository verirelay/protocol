package avr1

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

func TestReportDataAVR1GoldenVector(t *testing.T) {
	publicKey := ed25519.PublicKey{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	}
	nonce := []byte{
		0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
		0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
		0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
		0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
	}

	reportData, err := ReportDataAVR1(publicKey, nonce)
	if err != nil {
		t.Fatal(err)
	}
	const want = "aa1cc8565b4fa7f3a0bcab6e769f32e6f92dd463a7a11aee65a7749fa33c75e2908b97abe328f6253091027e0f8d3f4643e1f5c2b7e3433da902c3d328244682"
	if got := hex.EncodeToString(reportData[:]); got != want {
		t.Fatalf("report_data = %s, want %s", got, want)
	}
}

func TestReportDataAVR1ChangesWhenBoundInputsChange(t *testing.T) {
	publicKey := ed25519.PublicKey([]byte("0123456789abcdef0123456789abcdef"))
	nonce := []byte("abcdef0123456789abcdef0123456789")
	base, err := ReportDataAVR1(publicKey, nonce)
	if err != nil {
		t.Fatal(err)
	}
	changedKey := append(ed25519.PublicKey(nil), publicKey...)
	changedKey[0] ^= 0xff
	withKey, err := ReportDataAVR1(changedKey, nonce)
	if err != nil {
		t.Fatal(err)
	}
	changedNonce := append([]byte(nil), nonce...)
	changedNonce[0] ^= 0xff
	withNonce, err := ReportDataAVR1(publicKey, changedNonce)
	if err != nil {
		t.Fatal(err)
	}
	if base == withKey || base == withNonce || withKey == withNonce {
		t.Fatalf("report_data did not change for changed binding inputs")
	}
}

func TestReportDataAVR1RejectsInvalidLengths(t *testing.T) {
	if _, err := ReportDataAVR1(ed25519.PublicKey([]byte("short")), []byte("abcdef0123456789abcdef0123456789")); err == nil || !strings.Contains(err.Error(), "public_key length") {
		t.Fatalf("short public key err = %v", err)
	}
	if _, err := ReportDataAVR1(ed25519.PublicKey([]byte("0123456789abcdef0123456789abcdef")), []byte("short")); err == nil || !strings.Contains(err.Error(), "nonce length") {
		t.Fatalf("short nonce err = %v", err)
	}
}

func TestDecodeNonceBase64URL(t *testing.T) {
	nonce := []byte("abcdef0123456789abcdef0123456789")
	encoded := base64.RawURLEncoding.EncodeToString(nonce)
	decoded, err := DecodeNonceBase64URL(encoded)
	if err != nil || string(decoded) != string(nonce) {
		t.Fatalf("decoded nonce = %q, err = %v", decoded, err)
	}
	for _, value := range []string{"AQIDBA", encoded + "=", "%%%", flipPaddingBit(encoded)} {
		if _, err := DecodeNonceBase64URL(value); err == nil {
			t.Fatalf("invalid nonce %q was accepted", value)
		}
	}
}
