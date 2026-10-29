package wire

import (
	"encoding/json"
	"strings"
	"testing"
)

type inner struct {
	Name string `json:"name"`
}

type outer struct {
	Version  string           `json:"version"`
	Inner    inner            `json:"inner"`
	List     []inner          `json:"list"`
	Map      map[string]inner `json:"map"`
	Pointer  *inner           `json:"pointer"`
	Optional string           `json:"optional,omitempty"`
	Raw      json.RawMessage  `json:"raw"`
	Any      any              `json:"any"`
	Ignored  string           `json:"-"`
	Untagged string
}

func TestDecodeAcceptsKnownFields(t *testing.T) {
	data := `{"version":"x","inner":{"name":"a"},"list":[{"name":"b"}],"map":{"k":{"name":"c"}},"pointer":{"name":"d"},"optional":"e","raw":{"anything":[1,{"x":2}]},"any":{"y":[3]},"Untagged":"f"}`
	for name, decode := range map[string]func([]byte, any) error{"strict": DecodeStrict, "lenient": DecodeLenient} {
		var got outer
		if err := decode([]byte(data), &got); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got.Version != "x" || got.Inner.Name != "a" || got.List[0].Name != "b" || got.Map["k"].Name != "c" || got.Pointer.Name != "d" || got.Optional != "e" || got.Untagged != "f" {
			t.Fatalf("%s: decoded %+v", name, got)
		}
	}
}

func TestDecodeRejectsInBothModes(t *testing.T) {
	for _, data := range []string{
		``, `null`, `[]`, `"x"`, `1`, `{`, `{} {}`, `{} x`, `{}}`,
		`{"version":"a","version":"b"}`,
		`{"inner":{"name":"a","name":"b"}}`,
		`{"list":[{"name":"a","name":"b"}]}`,
		`{"raw":{"x":1,"x":2}}`,
		`{"unknown":{"x":1,"x":2}}`,
		`{"version":"a","version":"b"}`,
		`{"Version":"x"}`,
		`{"inner":{"NAME":"x"}}`,
		`{"untagged":"x"}`,
		`{"version":1}`,
	} {
		for name, decode := range map[string]func([]byte, any) error{"strict": DecodeStrict, "lenient": DecodeLenient} {
			var got outer
			if err := decode([]byte(data), &got); err == nil {
				t.Errorf("%s accepted %q", name, data)
			}
		}
	}
}

func TestDecodeUnknownFieldsAndOptionalValues(t *testing.T) {
	for _, tc := range []struct {
		data    string
		lenient bool
		detail  string
	}{
		{data: `{"unknown":1}`, lenient: true, detail: `unknown JSON field "unknown"`},
		{data: `{"inner":{"unknown":1}}`, lenient: true, detail: `unknown JSON field "inner.unknown"`},
		{data: `{"list":[{"name":"a"},{"unknown":1}]}`, lenient: true, detail: `unknown JSON field "list[1].unknown"`},
		{data: `{"map":{"k":{"unknown":1}}}`, lenient: true, detail: `unknown JSON field "map.k.unknown"`},
		{data: `{"pointer":{"unknown":1}}`, lenient: true, detail: `unknown JSON field "pointer.unknown"`},
		{data: `{"Ignored":"x"}`, lenient: true, detail: `unknown JSON field "Ignored"`},
		{data: `{"optional":""}`, lenient: true, detail: `optional JSON field "optional" must be omitted instead of empty`},
		{data: `{"optional":null}`, lenient: true, detail: `optional JSON field "optional" must be omitted instead of empty`},
		{data: `{"version":"x","version":"x"}`, detail: `duplicate JSON key "version"`},
		{data: `{"Version":"x"}`, detail: `JSON key "Version" must match its field name exactly`},
	} {
		var strict outer
		err := DecodeStrict([]byte(tc.data), &strict)
		if err == nil || !strings.Contains(err.Error(), tc.detail) {
			t.Errorf("strict %s: err = %v, want %q", tc.data, err, tc.detail)
		}
		var lenient outer
		if err := DecodeLenient([]byte(tc.data), &lenient); (err == nil) != tc.lenient {
			t.Errorf("lenient %s: err = %v, want accepted %v", tc.data, err, tc.lenient)
		}
	}
}

func TestDecodeBase64URL(t *testing.T) {
	if got, err := DecodeBase64URL("AQID"); err != nil || string(got) != "\x01\x02\x03" {
		t.Fatalf("DecodeBase64URL = %x, %v", got, err)
	}
	if got, err := DecodeBase64URL(""); err != nil || len(got) != 0 {
		t.Fatalf("DecodeBase64URL(empty) = %x, %v", got, err)
	}
	for _, value := range []string{"AQID=", "AQ==", "AQ+", "AQ/", "AR", "AQ\nID", "%%%", "A"} {
		if _, err := DecodeBase64URL(value); err == nil {
			t.Errorf("accepted %q", value)
		}
	}
}
