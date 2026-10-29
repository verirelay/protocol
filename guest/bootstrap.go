package guest

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/verirelay/protocol/internal/wire"
)

// Bootstrap identifiers and the largest Bootstrap file, in bytes.
const (
	BootstrapVersion  = "veriprov-bootstrap/1"
	BootstrapProtocol = "veriprov/1"
	MaxBootstrapSize  = 4096
)

var profilePattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// Bootstrap names the VeriProv origin the Guest provisions its Runtime Config
// from and the VeriProv identity key that signs it. Its exact file bytes are
// bound to the Attestation Report through HOST_DATA.
type Bootstrap struct {
	Version           string `json:"version"`
	Protocol          string `json:"protocol"`
	URL               string `json:"url"`
	IdentityPublicKey string `json:"identity_public_key"`
	Profile           string `json:"profile,omitempty"`
}

// DecodeBootstrap decodes a Bootstrap file strictly. data must be at most
// MaxBootstrapSize bytes, contain no NUL byte, and be one JSON object without
// duplicate keys and without fields beyond those of Bootstrap; profile, when
// present, must not be empty or null. It does not check field values; call
// Bootstrap.Validate for that.
func DecodeBootstrap(data []byte) (Bootstrap, error) {
	if len(data) > MaxBootstrapSize {
		return Bootstrap{}, fmt.Errorf("bootstrap is %d bytes, want at most %d", len(data), MaxBootstrapSize)
	}
	if bytes.IndexByte(data, 0) >= 0 {
		return Bootstrap{}, errors.New("bootstrap must not contain a NUL byte")
	}
	var bootstrap Bootstrap
	if err := wire.DecodeStrict(data, &bootstrap); err != nil {
		return Bootstrap{}, fmt.Errorf("decode bootstrap: %w", err)
	}
	return bootstrap, nil
}

// Validate requires the BootstrapVersion version and BootstrapProtocol
// protocol, an HTTPS origin url (an explicit port is allowed; user info, path,
// query and fragment are not), an identity_public_key that IdentityKey
// decodes, and a profile that is empty or 1 to 64 characters of
// [A-Za-z0-9._-].
func (b Bootstrap) Validate() error {
	if b.Version != BootstrapVersion {
		return fmt.Errorf("version = %q, want %q", b.Version, BootstrapVersion)
	}
	if b.Protocol != BootstrapProtocol {
		return fmt.Errorf("protocol = %q, want %q", b.Protocol, BootstrapProtocol)
	}
	parsed, err := url.Parse(b.URL)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil || parsed.Path != "" || strings.ContainsAny(b.URL, "?#") {
		return errors.New("url must be an HTTPS origin")
	}
	if _, err := b.IdentityKey(); err != nil {
		return err
	}
	if b.Profile != "" && !profilePattern.MatchString(b.Profile) {
		return errors.New("profile must be 1 to 64 characters of [A-Za-z0-9._-]")
	}
	return nil
}

// IdentityKey decodes identity_public_key: canonical unpadded base64url of a
// 32-byte Ed25519 public key.
func (b Bootstrap) IdentityKey() (ed25519.PublicKey, error) {
	key, err := wire.DecodeBase64URL(b.IdentityPublicKey)
	if err != nil {
		return nil, fmt.Errorf("identity_public_key: %w", err)
	}
	if len(key) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("identity_public_key decodes to %d bytes, want %d", len(key), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(key), nil
}

// HostData returns the SEV-SNP HOST_DATA that binds a Bootstrap: the SHA-256
// of the exact Bootstrap file bytes.
func HostData(bootstrap []byte) [sha256.Size]byte {
	return sha256.Sum256(bootstrap)
}

// BootstrapFromConfigDisk returns the Bootstrap file at the start of the config
// disk: the bytes before the first NUL. disk must contain a NUL, which proves
// the Bootstrap is followed by padding, and the Bootstrap must be non-empty and
// at most MaxBootstrapSize bytes. The result aliases disk.
func BootstrapFromConfigDisk(disk []byte) ([]byte, error) {
	end := bytes.IndexByte(disk[:min(len(disk), MaxBootstrapSize+1)], 0)
	switch {
	case end == 0:
		return nil, errors.New("config disk holds no bootstrap")
	case end > 0:
		return disk[:end], nil
	case len(disk) > MaxBootstrapSize:
		return nil, fmt.Errorf("config disk bootstrap exceeds %d bytes", MaxBootstrapSize)
	default:
		return nil, errors.New("config disk has no NUL padding after the bootstrap")
	}
}
