package veriprov1

import (
	"net/http"
	"testing"
)

func TestStatusForError(t *testing.T) {
	for code, want := range map[ErrorCode]int{
		ErrMalformedJSON:          http.StatusBadRequest,
		ErrInvalidField:           http.StatusBadRequest,
		ErrBodyTooLarge:           http.StatusRequestEntityTooLarge,
		ErrChallengeNotFound:      http.StatusNotFound,
		ErrChallengeExpired:       http.StatusConflict,
		ErrReportDataMismatch:     http.StatusConflict,
		ErrPolicyDenied:           http.StatusConflict,
		ErrHPKEFailure:            http.StatusServiceUnavailable,
		ErrUnavailable:            http.StatusServiceUnavailable,
		ErrInternal:               http.StatusInternalServerError,
		"challenge.already_used":  http.StatusInternalServerError,
		"attestation.unsupported": http.StatusInternalServerError,
	} {
		if got := StatusForError(code); got != want {
			t.Errorf("StatusForError(%s) = %d, want %d", code, got, want)
		}
	}
}
