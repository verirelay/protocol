package veriprov1

import (
	"encoding/json"

	"github.com/verirelay/protocol/internal/wire"
)

// DecodeJSON decodes data into v by the veriprov/1 rules, which apply to every
// message and to the Runtime Config: data must be exactly one JSON object,
// duplicate keys are rejected at every depth, and unknown fields are ignored.
// It does not check required fields or values; call the type's Validate
// method for that.
func DecodeJSON(data []byte, v any) error {
	return wire.DecodeLenient(data, v)
}

// MarshalJSON returns the json.Marshal encoding of value.
func MarshalJSON(value any) ([]byte, error) {
	return json.Marshal(value)
}
