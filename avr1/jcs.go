package avr1

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"slices"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

var (
	errInvalidJCSNumber   = errors.New("invalid jcs number")
	errMultipleJSONValues = errors.New("multiple json values")
)

// canonicalizeJSON returns the JCS (RFC 8785) canonical form of jsonData, which
// must hold exactly one JSON value. Object keys are sorted by UTF-16 code units
// and numbers are re-encoded from their float64 value.
func canonicalizeJSON(jsonData []byte) ([]byte, error) {
	var value any
	if err := decodeSingleJSONValue(jsonData, &value); err != nil {
		return nil, err
	}
	var out bytes.Buffer
	if err := writeJCSValue(&out, value); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// canonicalize encodes value with encoding/json (HTML escaping disabled) and
// returns canonicalizeJSON of the result.
func canonicalize(value any) ([]byte, error) {
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return canonicalizeJSON(bytes.TrimSpace(buf.Bytes()))
}

// decodeSingleJSONValue decodes exactly one JSON value into value. Numbers stay
// json.Number, which writeJCSValue formats from their float64 value.
func decodeSingleJSONValue(data []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	var trailing any
	switch err := decoder.Decode(&trailing); {
	case err == nil:
		return errMultipleJSONValues
	case errors.Is(err, io.EOF):
		return nil
	default:
		return err
	}
}

func writeJCSValue(out *bytes.Buffer, value any) error {
	switch v := value.(type) {
	case nil:
		out.WriteString("null")
	case bool:
		if v {
			out.WriteString("true")
		} else {
			out.WriteString("false")
		}
	case string:
		out.WriteString(quoteJCSString(v))
	case json.Number:
		n, err := formatJCSNumber(v)
		if err != nil {
			return err
		}
		out.WriteString(n)
	case []any:
		out.WriteByte('[')
		for i, item := range v {
			if i > 0 {
				out.WriteByte(',')
			}
			if err := writeJCSValue(out, item); err != nil {
				return err
			}
		}
		out.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(v))
		for key := range v {
			keys = append(keys, key)
		}
		sort.Slice(keys, func(i, j int) bool { return compareUTF16(keys[i], keys[j]) < 0 })
		out.WriteByte('{')
		for i, key := range keys {
			if i > 0 {
				out.WriteByte(',')
			}
			out.WriteString(quoteJCSString(key))
			out.WriteByte(':')
			if err := writeJCSValue(out, v[key]); err != nil {
				return err
			}
		}
		out.WriteByte('}')
	}
	return nil
}

func quoteJCSString(value string) string {
	var out bytes.Buffer
	out.WriteByte('"')
	for _, r := range value {
		switch r {
		case '\b':
			out.WriteString(`\b`)
		case '\t':
			out.WriteString(`\t`)
		case '\n':
			out.WriteString(`\n`)
		case '\f':
			out.WriteString(`\f`)
		case '\r':
			out.WriteString(`\r`)
		case '"':
			out.WriteString(`\"`)
		case '\\':
			out.WriteString(`\\`)
		default:
			if r < 0x20 {
				_, _ = fmt.Fprintf(&out, `\u%04x`, r)
			} else {
				out.WriteRune(r)
			}
		}
	}
	out.WriteByte('"')
	return out.String()
}

func formatJCSNumber(number json.Number) (string, error) {
	f, err := strconv.ParseFloat(number.String(), 64)
	if err != nil {
		return "", err
	}
	return formatJCSFloat(f)
}

func formatJCSFloat(f float64) (string, error) {
	if math.IsInf(f, 0) || math.IsNaN(f) {
		return "", errInvalidJCSNumber
	}
	if f == 0 {
		return "0", nil
	}
	abs := math.Abs(f)
	var s string
	if abs >= 1e-6 && abs < 1e21 {
		s = strconv.FormatFloat(f, 'f', -1, 64)
	} else {
		s = strconv.FormatFloat(f, 'e', -1, 64)
		s = normalizeExponent(s)
	}
	return s, nil
}

func normalizeExponent(s string) string {
	mantissa, exp, found := strings.Cut(s, "e")
	if !found {
		return s
	}
	sign := ""
	if strings.HasPrefix(exp, "+") || strings.HasPrefix(exp, "-") {
		sign = exp[:1]
		exp = exp[1:]
	}
	exp = strings.TrimLeft(exp, "0")
	if exp == "" {
		exp = "0"
	}
	if sign == "-" {
		return mantissa + "e-" + exp
	}
	return mantissa + "e+" + exp
}

func compareUTF16(a, b string) int {
	return slices.Compare(utf16Units(a), utf16Units(b))
}

func utf16Units(s string) []uint16 {
	units := make([]uint16, 0, len(s))
	for len(s) > 0 {
		r, size := utf8.DecodeRuneInString(s)
		if r == utf8.RuneError && size == 1 {
			panic(fmt.Sprintf("invalid utf-8 string: %q", s))
		}
		units = append(units, utf16.Encode([]rune{r})...)
		s = s[size:]
	}
	return units
}
