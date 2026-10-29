// Package wire implements the decoding rules shared by every Protocol format.
package wire

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
)

// DecodeStrict decodes data into v by the strict rules. data must be exactly
// one JSON object. At every depth, duplicate keys are rejected, and so is every
// key that does not exactly name a field of v's type. An optional field
// (tagged omitempty) must not be null or the empty string when present.
//
// The types reachable from v must not embed structs.
func DecodeStrict(data []byte, v any) error {
	return decode(data, v, true)
}

// DecodeLenient decodes data into v by the lenient rules. It is DecodeStrict
// except that keys naming no field are ignored and optional fields may be
// empty. A key that matches a field only case-insensitively is still rejected,
// because encoding/json would bind it to that field.
func DecodeLenient(data []byte, v any) error {
	return decode(data, v, false)
}

func decode(data []byte, v any, strict bool) error {
	s := scanner{decoder: json.NewDecoder(bytes.NewReader(data)), strict: strict}
	s.decoder.UseNumber()
	token, err := s.decoder.Token()
	if err != nil {
		return err
	}
	if token != json.Delim('{') {
		return errors.New("JSON value must be an object")
	}
	if err := s.object("", reflect.TypeOf(v)); err != nil {
		return err
	}
	switch _, err := s.decoder.Token(); {
	case err == nil:
		return errors.New("unexpected data after the JSON object")
	case !errors.Is(err, io.EOF):
		return err
	}
	return json.Unmarshal(data, v)
}

// scanner walks the JSON tokens alongside the Go type they decode into. A nil
// type means the value is not checked against a Go type.
type scanner struct {
	decoder *json.Decoder
	strict  bool
}

type field struct {
	typ       reflect.Type
	omitempty bool
}

var unmarshalerType = reflect.TypeFor[json.Unmarshaler]()

// target dereferences pointers and returns nil for types that decode
// themselves.
func target(t reflect.Type) reflect.Type {
	for t != nil {
		if t.Implements(unmarshalerType) || reflect.PointerTo(t).Implements(unmarshalerType) {
			return nil
		}
		if t.Kind() != reflect.Pointer {
			return t
		}
		t = t.Elem()
	}
	return nil
}

func (s scanner) value(path string, token json.Token, t reflect.Type) error {
	switch token {
	case json.Delim('{'):
		return s.object(path, t)
	case json.Delim('['):
		return s.array(path, t)
	}
	return nil
}

func (s scanner) object(path string, t reflect.Type) error {
	t = target(t)
	var fields map[string]field
	var elem reflect.Type
	switch {
	case t == nil:
	case t.Kind() == reflect.Struct:
		fields = fieldsOf(t)
	case t.Kind() == reflect.Map:
		elem = t.Elem()
	}
	seen := make(map[string]struct{})
	for s.decoder.More() {
		token, err := s.decoder.Token()
		if err != nil {
			return err
		}
		key, ok := token.(string)
		if !ok {
			return errors.New("JSON object key is not a string")
		}
		keyPath := key
		if path != "" {
			keyPath = path + "." + key
		}
		if _, dup := seen[key]; dup {
			return fmt.Errorf("duplicate JSON key %q", keyPath)
		}
		seen[key] = struct{}{}
		next, err := s.decoder.Token()
		if err != nil {
			return err
		}
		valueType := elem
		if fields != nil {
			f, known := fields[key]
			switch {
			case known:
				valueType = f.typ
				if s.strict && f.omitempty && (next == nil || next == "") {
					return fmt.Errorf("optional JSON field %q must be omitted instead of empty", keyPath)
				}
			case foldsToField(fields, key):
				return fmt.Errorf("JSON key %q must match its field name exactly", keyPath)
			case s.strict:
				return fmt.Errorf("unknown JSON field %q", keyPath)
			}
		}
		if err := s.value(keyPath, next, valueType); err != nil {
			return err
		}
	}
	_, err := s.decoder.Token()
	return err
}

func (s scanner) array(path string, t reflect.Type) error {
	t = target(t)
	var elem reflect.Type
	if t != nil && (t.Kind() == reflect.Slice || t.Kind() == reflect.Array) {
		elem = t.Elem()
	}
	for i := 0; s.decoder.More(); i++ {
		token, err := s.decoder.Token()
		if err != nil {
			return err
		}
		if err := s.value(fmt.Sprintf("%s[%d]", path, i), token, elem); err != nil {
			return err
		}
	}
	_, err := s.decoder.Token()
	return err
}

func fieldsOf(t reflect.Type) map[string]field {
	fields := make(map[string]field, t.NumField())
	for f := range t.Fields() {
		if !f.IsExported() {
			continue
		}
		tag := f.Tag.Get("json")
		if tag == "-" {
			continue
		}
		name, options, _ := strings.Cut(tag, ",")
		if name == "" {
			name = f.Name
		}
		fields[name] = field{typ: f.Type, omitempty: hasOption(options, "omitempty")}
	}
	return fields
}

func hasOption(options, option string) bool {
	for o := range strings.SplitSeq(options, ",") {
		if o == option {
			return true
		}
	}
	return false
}

// foldsToField reports whether key names a field only case-insensitively,
// the way encoding/json matches keys.
func foldsToField(fields map[string]field, key string) bool {
	for name := range fields {
		if strings.EqualFold(name, key) {
			return true
		}
	}
	return false
}
