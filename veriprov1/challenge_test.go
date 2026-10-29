package veriprov1

import (
	"testing"
	"time"
)

func TestChallengeResponseValidate(t *testing.T) {
	issuedAt := time.Date(2026, 7, 11, 7, 0, 0, 0, time.UTC)
	valid := ChallengeResponse{
		ChallengeID: EncodeBase64URL(make([]byte, 56)),
		Nonce:       EncodeBase64URL(make([]byte, NonceSize)),
		IssuedAt:    FormatUTCTime(issuedAt),
		ExpiresAt:   FormatUTCTime(issuedAt.Add(time.Minute)),
		TTLSeconds:  60,
	}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	expired := valid
	expired.IssuedAt, expired.ExpiresAt = "2000-01-01T00:00:00Z", "2000-01-01T00:01:00Z"
	if err := expired.Validate(); err != nil {
		t.Fatalf("Validate judged expiry by the clock: %v", err)
	}
	for name, mutate := range map[string]func(*ChallengeResponse){
		"short challenge_id":    func(r *ChallengeResponse) { r.ChallengeID = EncodeBase64URL(make([]byte, MinimumChallengeIDSize-1)) },
		"padded challenge_id":   func(r *ChallengeResponse) { r.ChallengeID += "=" },
		"short nonce":           func(r *ChallengeResponse) { r.Nonce = EncodeBase64URL(make([]byte, NonceSize-1)) },
		"non-UTC issued_at":     func(r *ChallengeResponse) { r.IssuedAt = "2026-07-11T15:00:00+08:00" },
		"fractional expires_at": func(r *ChallengeResponse) { r.ExpiresAt = "2026-07-11T07:01:00.5Z" },
		"expires before issued": func(r *ChallengeResponse) { r.ExpiresAt = r.IssuedAt },
		"zero ttl":              func(r *ChallengeResponse) { r.TTLSeconds = 0 },
	} {
		response := valid
		mutate(&response)
		if err := response.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
