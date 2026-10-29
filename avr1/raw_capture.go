package avr1

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/verirelay/protocol/internal/wire"
)

// Raw Capture identifiers. RawCaptureKeySize is the length of the AES-256 key
// the client receives as X-VeriRelay-Store-Key.
const (
	RawCaptureVersion          = "verirelay-raw-capture/1"
	RawCapturePlaintextVersion = "verirelay-raw-capture-plaintext/1"
	RawCaptureAlgorithm        = "AES-256-GCM"
	RawCaptureKeySize          = 32
)

// rawCaptureNonceSize is the standard AES-GCM nonce length.
const rawCaptureNonceSize = 12

// RawCapture is the Raw Capture envelope: the AES-256-GCM encryption of a
// RawCapturePlaintext under the per-capture key, with the AAD
// RawCaptureVersion + ":" + store_id.
type RawCapture struct {
	Version    string `json:"version"`
	Algorithm  string `json:"algorithm"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

// RawCapturePlaintext is the plaintext of a RawCapture: the base64url of the
// exact request and response body bytes.
type RawCapturePlaintext struct {
	Version      string `json:"version"`
	RequestBody  string `json:"request_body"`
	ResponseBody string `json:"response_body"`
}

// DecodeRawCapture decodes a Raw Capture envelope leniently: data must be one
// JSON object without duplicate keys, and unknown fields are ignored. It does
// not check field values; OpenRawCapture does.
func DecodeRawCapture(data []byte) (RawCapture, error) {
	var capture RawCapture
	if err := wire.DecodeLenient(data, &capture); err != nil {
		return RawCapture{}, err
	}
	return capture, nil
}

// SealRawCapture encrypts requestBody and responseBody under key, a
// RawCaptureKeySize-byte key, for storeID, with a random nonce.
func SealRawCapture(key []byte, storeID string, requestBody, responseBody []byte) (RawCapture, error) {
	nonce := make([]byte, rawCaptureNonceSize)
	_, _ = rand.Read(nonce)
	return sealRawCapture(key, nonce, storeID, requestBody, responseBody)
}

func sealRawCapture(key, nonce []byte, storeID string, requestBody, responseBody []byte) (RawCapture, error) {
	gcm, err := rawCaptureAEAD(key, storeID)
	if err != nil {
		return RawCapture{}, err
	}
	plaintext, err := json.Marshal(RawCapturePlaintext{
		Version:      RawCapturePlaintextVersion,
		RequestBody:  wire.EncodeBase64URL(requestBody),
		ResponseBody: wire.EncodeBase64URL(responseBody),
	})
	if err != nil {
		return RawCapture{}, err
	}
	return RawCapture{
		Version:    RawCaptureVersion,
		Algorithm:  RawCaptureAlgorithm,
		Nonce:      wire.EncodeBase64URL(nonce),
		Ciphertext: wire.EncodeBase64URL(gcm.Seal(nil, nonce, plaintext, rawCaptureAAD(storeID))),
	}, nil
}

// OpenRawCapture decrypts capture with key for storeID and returns the request
// and response bodies. The plaintext is decoded leniently.
func OpenRawCapture(key []byte, storeID string, capture RawCapture) (requestBody, responseBody []byte, err error) {
	if capture.Version != RawCaptureVersion {
		return nil, nil, fmt.Errorf("version = %q, want %q", capture.Version, RawCaptureVersion)
	}
	if capture.Algorithm != RawCaptureAlgorithm {
		return nil, nil, fmt.Errorf("algorithm = %q, want %q", capture.Algorithm, RawCaptureAlgorithm)
	}
	gcm, err := rawCaptureAEAD(key, storeID)
	if err != nil {
		return nil, nil, err
	}
	nonce, err := wire.DecodeBase64URL(capture.Nonce)
	if err != nil || len(nonce) != rawCaptureNonceSize {
		return nil, nil, fmt.Errorf("nonce must be base64url of %d bytes", rawCaptureNonceSize)
	}
	ciphertext, err := wire.DecodeBase64URL(capture.Ciphertext)
	if err != nil {
		return nil, nil, fmt.Errorf("ciphertext %w", err)
	}
	data, err := gcm.Open(nil, nonce, ciphertext, rawCaptureAAD(storeID))
	if err != nil {
		return nil, nil, errors.New("raw capture authentication failed: wrong key or store_id, or altered ciphertext")
	}
	var plaintext RawCapturePlaintext
	if err := wire.DecodeLenient(data, &plaintext); err != nil {
		return nil, nil, fmt.Errorf("decode raw capture plaintext: %w", err)
	}
	if plaintext.Version != RawCapturePlaintextVersion {
		return nil, nil, fmt.Errorf("plaintext version = %q, want %q", plaintext.Version, RawCapturePlaintextVersion)
	}
	if requestBody, err = wire.DecodeBase64URL(plaintext.RequestBody); err != nil {
		return nil, nil, fmt.Errorf("request_body %w", err)
	}
	if responseBody, err = wire.DecodeBase64URL(plaintext.ResponseBody); err != nil {
		return nil, nil, fmt.Errorf("response_body %w", err)
	}
	return requestBody, responseBody, nil
}

func rawCaptureAEAD(key []byte, storeID string) (cipher.AEAD, error) {
	if len(key) != RawCaptureKeySize {
		return nil, fmt.Errorf("raw capture key length = %d, want %d", len(key), RawCaptureKeySize)
	}
	if storeID == "" {
		return nil, errors.New("store_id must not be empty")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func rawCaptureAAD(storeID string) []byte {
	return []byte(RawCaptureVersion + ":" + storeID)
}
