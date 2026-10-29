package guest

import (
	"bytes"
	"crypto/sha256"
	"strings"
	"testing"
)

// testIdentityKey is the unpadded base64url of 32 zero bytes.
const testIdentityKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

const validBootstrapJSON = `{"version":"veriprov-bootstrap/1","protocol":"veriprov/1","url":"https://veriprov.example.com","identity_public_key":"` + testIdentityKey + `","profile":"prod-eu.1"}`

func validBootstrap() Bootstrap {
	return Bootstrap{
		Version:           BootstrapVersion,
		Protocol:          BootstrapProtocol,
		URL:               "https://veriprov.example.com",
		IdentityPublicKey: testIdentityKey,
		Profile:           "prod-eu.1",
	}
}

func TestDecodeBootstrap(t *testing.T) {
	bootstrap, err := DecodeBootstrap([]byte(validBootstrapJSON))
	if err != nil {
		t.Fatal(err)
	}
	if bootstrap != validBootstrap() {
		t.Fatalf("decoded %+v", bootstrap)
	}
	if err := bootstrap.Validate(); err != nil {
		t.Fatal(err)
	}
	key, err := bootstrap.IdentityKey()
	if err != nil || !bytes.Equal(key, make([]byte, 32)) {
		t.Fatalf("IdentityKey = %x, %v", key, err)
	}
	withoutProfile := strings.Replace(validBootstrapJSON, `,"profile":"prod-eu.1"`, "", 1)
	if bootstrap, err := DecodeBootstrap([]byte(withoutProfile)); err != nil || bootstrap.Profile != "" || bootstrap.Validate() != nil {
		t.Fatalf("bootstrap without profile = %+v, %v", bootstrap, err)
	}
}

func TestDecodeBootstrapIsStrict(t *testing.T) {
	padded := validBootstrapJSON + strings.Repeat(" ", MaxBootstrapSize-len(validBootstrapJSON))
	if _, err := DecodeBootstrap([]byte(padded)); err != nil {
		t.Fatalf("bootstrap of exactly %d bytes: %v", MaxBootstrapSize, err)
	}
	for name, data := range map[string]string{
		"too large":         padded + " ",
		"NUL":               validBootstrapJSON + "\x00",
		"unknown field":     strings.Replace(validBootstrapJSON, `"url"`, `"tls_spki_sha256":"x","url"`, 1),
		"duplicate key":     strings.Replace(validBootstrapJSON, `"url"`, `"version":"veriprov-bootstrap/1","url"`, 1),
		"case-folded key":   strings.Replace(validBootstrapJSON, `"url"`, `"URL"`, 1),
		"empty profile":     strings.Replace(validBootstrapJSON, `"prod-eu.1"`, `""`, 1),
		"null profile":      strings.Replace(validBootstrapJSON, `"prod-eu.1"`, `null`, 1),
		"not an object":     `[]`,
		"two JSON values":   validBootstrapJSON + validBootstrapJSON,
		"invalid JSON":      validBootstrapJSON[:len(validBootstrapJSON)-1],
		"empty file":        ``,
		"wrong field types": strings.Replace(validBootstrapJSON, `"https://veriprov.example.com"`, `1`, 1),
	} {
		if _, err := DecodeBootstrap([]byte(data)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestBootstrapValidateRejectsEachRule(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*Bootstrap)
	}{
		{"old version", func(b *Bootstrap) { b.Version = "veriprov-bootstrap-v1" }},
		{"protocol", func(b *Bootstrap) { b.Protocol = "veriprov/2" }},
		{"http url", func(b *Bootstrap) { b.URL = "http://veriprov.example.com" }},
		{"url path", func(b *Bootstrap) { b.URL = "https://veriprov.example.com/v1" }},
		{"url slash", func(b *Bootstrap) { b.URL = "https://veriprov.example.com/" }},
		{"url user info", func(b *Bootstrap) { b.URL = "https://user@veriprov.example.com" }},
		{"url query", func(b *Bootstrap) { b.URL = "https://veriprov.example.com?x=1" }},
		{"url empty query", func(b *Bootstrap) { b.URL = "https://veriprov.example.com?" }},
		{"url fragment", func(b *Bootstrap) { b.URL = "https://veriprov.example.com#x" }},
		{"url without host", func(b *Bootstrap) { b.URL = "https://:443" }},
		{"empty url", func(b *Bootstrap) { b.URL = "" }},
		{"empty key", func(b *Bootstrap) { b.IdentityPublicKey = "" }},
		{"short key", func(b *Bootstrap) { b.IdentityPublicKey = testIdentityKey[:42] }},
		{"padded key", func(b *Bootstrap) { b.IdentityPublicKey = testIdentityKey + "=" }},
		{"standard base64 key", func(b *Bootstrap) { b.IdentityPublicKey = "+" + testIdentityKey[1:] }},
		{"non-canonical key", func(b *Bootstrap) { b.IdentityPublicKey = testIdentityKey[:42] + "B" }},
		{"profile too long", func(b *Bootstrap) { b.Profile = strings.Repeat("a", 65) }},
		{"profile character", func(b *Bootstrap) { b.Profile = "prod/eu" }},
		{"profile space", func(b *Bootstrap) { b.Profile = "prod eu" }},
	} {
		bootstrap := validBootstrap()
		tc.mutate(&bootstrap)
		if err := bootstrap.Validate(); err == nil {
			t.Errorf("%s: accepted %+v", tc.name, bootstrap)
		}
	}
	for _, mutate := range []func(*Bootstrap){
		func(b *Bootstrap) { b.URL = "https://veriprov.example.com:8443" },
		func(b *Bootstrap) { b.Profile = strings.Repeat("a", 64) },
		func(b *Bootstrap) { b.Profile = "A-z_0.9" },
	} {
		bootstrap := validBootstrap()
		mutate(&bootstrap)
		if err := bootstrap.Validate(); err != nil {
			t.Errorf("rejected %+v: %v", bootstrap, err)
		}
	}
}

func TestHostData(t *testing.T) {
	data := []byte(validBootstrapJSON)
	if HostData(data) != sha256.Sum256(data) {
		t.Fatal("HostData is not the SHA-256 of the bootstrap bytes")
	}
	if HostData(data) == HostData(append(data, ' ')) {
		t.Fatal("HostData ignored a trailing byte")
	}
}

func TestBootstrapFromConfigDisk(t *testing.T) {
	bootstrap := []byte(validBootstrapJSON)
	disk := append(append([]byte(nil), bootstrap...), make([]byte, 64<<10-len(bootstrap))...)
	got, err := BootstrapFromConfigDisk(disk)
	if err != nil || !bytes.Equal(got, bootstrap) {
		t.Fatalf("BootstrapFromConfigDisk = %q, %v", got, err)
	}
	maxSize := bytes.Repeat([]byte("x"), MaxBootstrapSize)
	if got, err := BootstrapFromConfigDisk(append(maxSize, 0)); err != nil || len(got) != MaxBootstrapSize {
		t.Fatalf("bootstrap of exactly %d bytes: %d, %v", MaxBootstrapSize, len(got), err)
	}
	for name, disk := range map[string][]byte{
		"no NUL":                bootstrap,
		"empty":                 {},
		"leading NUL":           make([]byte, 512),
		"too large":             append(append(maxSize, 'x'), 0),
		"too large without NUL": append(maxSize, 'x'),
	} {
		if got, err := BootstrapFromConfigDisk(disk); err == nil {
			t.Errorf("%s: returned %q", name, got)
		}
	}
}
