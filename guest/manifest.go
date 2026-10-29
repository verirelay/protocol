// Package guest defines the Guest Manifest, which VeriForge writes into the
// initrd, and the Bootstrap, which the host delivers to the CVM on the config
// disk and binds to the Attestation Report through HOST_DATA.
package guest

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"unicode"

	"github.com/verirelay/protocol/internal/wire"
)

// ManifestPath is where the Guest Manifest sits in the initrd.
const ManifestPath = "/etc/verirelay/manifest.json"

// Guest Manifest identifiers and the only accepted launch parameters.
const (
	ManifestVersion      = "verirelay-guest-manifest/1"
	LaunchProfileVersion = "verirelay-launch-profile/1"
	MeasurementProfile   = "sev-snp-qemu-direct-boot/1"
	VCPUType             = "EPYC-v4"
	GuestFeatures        = "0x1"
	KernelHashes         = true
)

var commitSHAPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)

// Manifest is the Guest Manifest at ManifestPath: the build sources and launch
// parameters of the Guest.
type Manifest struct {
	Version       string        `json:"version"`
	Source        Source        `json:"source"`
	LaunchProfile LaunchProfile `json:"launch_profile"`
}

// Source pins the VeriRelay and VeriForge sources of the Guest.
type Source struct {
	VeriRelay SourceRef `json:"verirelay"`
	VeriForge SourceRef `json:"veriforge"`
}

// SourceRef is a repository URL and commit SHA.
type SourceRef struct {
	Repository string `json:"repository"`
	Commit     string `json:"commit"`
}

// LaunchProfile records the SEV-SNP launch parameters of the Guest. The vCPU
// count is not part of it: the Launch Measurement covers it.
type LaunchProfile struct {
	Version            string `json:"version"`
	MeasurementProfile string `json:"measurement_profile"`
	VCPUType           string `json:"vcpu_type"`
	GuestFeatures      string `json:"guest_features"`
	KernelHashes       bool   `json:"kernel_hashes"`
	KernelAppend       string `json:"kernel_append"`
}

// DecodeManifest decodes a Guest Manifest strictly: data must be one JSON
// object without duplicate keys and without fields beyond those of Manifest, at
// any depth. It does not check field values; call Manifest.Validate for that.
func DecodeManifest(data []byte) (Manifest, error) {
	var manifest Manifest
	if err := wire.DecodeStrict(data, &manifest); err != nil {
		return Manifest{}, fmt.Errorf("decode guest manifest: %w", err)
	}
	return manifest, nil
}

// Validate checks every field rule of the Guest Manifest: the identifiers and
// launch parameters equal the constants of this package, repositories pass
// ValidateRepositoryURL, commits pass ValidateCommitSHA, and kernel_append is
// non-empty with no NUL, newline or other control character.
func (m Manifest) Validate() error {
	if m.Version != ManifestVersion {
		return fmt.Errorf("version = %q, want %q", m.Version, ManifestVersion)
	}
	if err := m.Source.VeriRelay.validate(); err != nil {
		return fmt.Errorf("source.verirelay.%w", err)
	}
	if err := m.Source.VeriForge.validate(); err != nil {
		return fmt.Errorf("source.veriforge.%w", err)
	}
	if err := m.LaunchProfile.validate(); err != nil {
		return fmt.Errorf("launch_profile.%w", err)
	}
	return nil
}

func (ref SourceRef) validate() error {
	if err := ValidateRepositoryURL(ref.Repository); err != nil {
		return fmt.Errorf("repository: %w", err)
	}
	if err := ValidateCommitSHA(ref.Commit); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}

func (profile LaunchProfile) validate() error {
	for _, check := range []struct{ field, got, want string }{
		{"version", profile.Version, LaunchProfileVersion},
		{"measurement_profile", profile.MeasurementProfile, MeasurementProfile},
		{"vcpu_type", profile.VCPUType, VCPUType},
		{"guest_features", profile.GuestFeatures, GuestFeatures},
	} {
		if check.got != check.want {
			return fmt.Errorf("%s = %q, want %q", check.field, check.got, check.want)
		}
	}
	if !profile.KernelHashes {
		return errors.New("kernel_hashes = false, want true")
	}
	if profile.KernelAppend == "" {
		return errors.New("kernel_append: must not be empty")
	}
	if strings.ContainsFunc(profile.KernelAppend, unicode.IsControl) {
		return errors.New("kernel_append: must not contain NUL, newline or other control characters")
	}
	return nil
}

// ValidateCommitSHA reports an error unless commit is a 40-character lowercase
// hex SHA.
func ValidateCommitSHA(commit string) error {
	if !commitSHAPattern.MatchString(commit) {
		return errors.New("must be a lowercase 40-character hexadecimal SHA")
	}
	return nil
}

// ValidateRepositoryURL reports an error unless raw is a canonical HTTPS
// repository URL: a lowercase host, a path with no trailing slash and no
// ".git" suffix, no user info, query or fragment, and no character that the
// URL's canonical serialization would escape or rewrite.
func ValidateRepositoryURL(raw string) error {
	if strings.ContainsAny(raw, "?#") {
		return errors.New("must not contain a query or fragment")
	}
	parsed, err := url.Parse(raw)
	switch {
	case err != nil:
		return errors.New("must be a URL")
	case parsed.Scheme != "https" || parsed.Host == "":
		return errors.New("must be an https URL with a host")
	case parsed.User != nil:
		return errors.New("must not contain user info")
	case parsed.Host != strings.ToLower(parsed.Host):
		return errors.New("host must be lowercase")
	case parsed.Path == "" || parsed.Path == "/":
		return errors.New("must have a repository path")
	case strings.HasSuffix(parsed.Path, "/"):
		return errors.New("must not end with a slash")
	case strings.HasSuffix(parsed.Path, ".git"):
		return errors.New(`must not end with ".git"`)
	case parsed.String() != raw:
		return errors.New("must be in canonical form")
	}
	return nil
}
