package veriprov1

import (
	"errors"
	"fmt"
	"time"
)

// ChallengeRequest is the challenge request body, an empty JSON object.
type ChallengeRequest struct{}

// ChallengeResponse is the challenge response body. ChallengeID is an opaque
// token chosen by VeriProv: a client sends it back unchanged and must not
// interpret it, and VeriProv alone decides whether it is valid or expired.
type ChallengeResponse struct {
	ChallengeID string `json:"challenge_id"`
	Nonce       string `json:"nonce"`
	IssuedAt    string `json:"issued_at"`
	ExpiresAt   string `json:"expires_at"`
	TTLSeconds  int    `json:"ttl_seconds"`
}

// Validate checks the challenge ID, the NonceSize-byte nonce, canonical
// RFC 3339 UTC issued_at and expires_at, a positive TTLSeconds, and that
// expires_at is after issued_at.
func (response ChallengeResponse) Validate() error {
	if err := validateChallengeID(response.ChallengeID); err != nil {
		return err
	}
	if _, err := DecodeBase64URL(response.Nonce, "nonce", NonceSize); err != nil {
		return err
	}
	issuedAt, err := parseUTCTime(response.IssuedAt, "issued_at")
	if err != nil {
		return err
	}
	expiresAt, err := parseUTCTime(response.ExpiresAt, "expires_at")
	if err != nil {
		return err
	}
	if response.TTLSeconds <= 0 {
		return errors.New("ttl_seconds must be positive")
	}
	if !expiresAt.After(issuedAt) {
		return errors.New("expires_at must be after issued_at")
	}
	return nil
}

func validateChallengeID(value string) error {
	_, err := decodeBase64URLMinSize(value, "challenge_id", MinimumChallengeIDSize)
	return err
}

// FormatUTCTime formats value in UTC as RFC 3339 with whole seconds, the
// canonical timestamp form of veriprov/1.
func FormatUTCTime(value time.Time) string {
	return value.UTC().Format(time.RFC3339)
}

func parseUTCTime(value, field string) (time.Time, error) {
	if value == "" {
		return time.Time{}, fmt.Errorf("%s must not be empty", field)
	}
	if value[len(value)-1] != 'Z' {
		return time.Time{}, fmt.Errorf("%s must use UTC Z form", field)
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("%s must be RFC3339 UTC: %w", field, err)
	}
	if FormatUTCTime(parsed) != value {
		return time.Time{}, fmt.Errorf("%s must use canonical RFC3339 UTC form", field)
	}
	return parsed, nil
}
