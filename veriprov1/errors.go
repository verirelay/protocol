package veriprov1

import "net/http"

// ErrorCode is a veriprov/1 error code.
type ErrorCode string

// Error codes of veriprov/1; StatusForError maps them to HTTP statuses.
const (
	ErrMalformedJSON      ErrorCode = "invalid_request.malformed_json"
	ErrInvalidField       ErrorCode = "invalid_request.invalid_field"
	ErrBodyTooLarge       ErrorCode = "invalid_request.body_too_large"
	ErrChallengeNotFound  ErrorCode = "challenge.not_found"
	ErrChallengeExpired   ErrorCode = "challenge.expired"
	ErrReportDataMismatch ErrorCode = "attestation.report_data_mismatch"
	ErrPolicyDenied       ErrorCode = "policy.denied"
	ErrHPKEFailure        ErrorCode = "envelope.hpke_failed"
	ErrUnavailable        ErrorCode = "service.unavailable"
	ErrInternal           ErrorCode = "internal.error"
)

// ErrorResponse is the JSON body of an error response.
type ErrorResponse struct {
	Error ErrorBody `json:"error"`
}

// ErrorBody is the error object of an ErrorResponse.
type ErrorBody struct {
	Code      ErrorCode `json:"code"`
	Message   string    `json:"message"`
	RequestID string    `json:"request_id,omitempty"`
}

// StatusForError returns the HTTP status for code. Unknown codes map to 500.
func StatusForError(code ErrorCode) int {
	switch code {
	case ErrMalformedJSON, ErrInvalidField:
		return http.StatusBadRequest
	case ErrBodyTooLarge:
		return http.StatusRequestEntityTooLarge
	case ErrChallengeNotFound:
		return http.StatusNotFound
	case ErrChallengeExpired, ErrReportDataMismatch, ErrPolicyDenied:
		return http.StatusConflict
	case ErrUnavailable, ErrHPKEFailure:
		return http.StatusServiceUnavailable
	default:
		return http.StatusInternalServerError
	}
}
