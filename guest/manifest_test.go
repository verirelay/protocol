package guest

import (
	"strings"
	"testing"
)

const validCommit = "0123456789abcdef0123456789abcdef01234567"

func validManifest() Manifest {
	return Manifest{
		Version: ManifestVersion,
		Source: Source{
			VeriRelay: SourceRef{Repository: "https://github.com/verirelay/verirelay", Commit: validCommit},
			VeriForge: SourceRef{Repository: "https://github.com/verirelay/veriforge", Commit: validCommit},
		},
		LaunchProfile: LaunchProfile{
			Version:            LaunchProfileVersion,
			MeasurementProfile: MeasurementProfile,
			VCPUType:           VCPUType,
			GuestFeatures:      GuestFeatures,
			KernelHashes:       KernelHashes,
			KernelAppend:       "console=ttyS0 panic=1",
		},
	}
}

const validManifestJSON = `{
  "version": "verirelay-guest-manifest/1",
  "source": {
    "verirelay": {"repository": "https://github.com/verirelay/verirelay", "commit": "0123456789abcdef0123456789abcdef01234567"},
    "veriforge": {"repository": "https://github.com/verirelay/veriforge", "commit": "0123456789abcdef0123456789abcdef01234567"}
  },
  "launch_profile": {
    "version": "verirelay-launch-profile/1",
    "measurement_profile": "sev-snp-qemu-direct-boot/1",
    "vcpu_type": "EPYC-v4",
    "guest_features": "0x1",
    "kernel_hashes": true,
    "kernel_append": "console=ttyS0 panic=1"
  }
}
`

func TestDecodeManifest(t *testing.T) {
	manifest, err := DecodeManifest([]byte(validManifestJSON))
	if err != nil {
		t.Fatal(err)
	}
	if manifest != validManifest() {
		t.Fatalf("decoded %+v", manifest)
	}
	if err := manifest.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestDecodeManifestIsStrict(t *testing.T) {
	for name, edit := range map[string][2]string{
		"unknown top-level":    {`"version"`, `"extra": 1, "version"`},
		"unknown source":       {`"verirelay": {`, `"verirelay": {"tag": "v1", `},
		"unknown profile":      {`"vcpu_type"`, `"vcpus": 1, "vcpu_type"`},
		"removed provisioning": {`"source"`, `"provisioning": {}, "source"`},
		"duplicate key":        {`"guest_features": "0x1"`, `"guest_features": "0x1", "guest_features": "0x1"`},
		"case-folded key":      {`"kernel_hashes"`, `"Kernel_Hashes"`},
		"trailing value":       {"}\n}\n", "}\n} {}"},
	} {
		data := strings.Replace(validManifestJSON, edit[0], edit[1], 1)
		if data == validManifestJSON {
			t.Fatalf("%s: edit did not apply", name)
		}
		if _, err := DecodeManifest([]byte(data)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestManifestValidateRejectsEachRule(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*Manifest)
		detail string
	}{
		{"version", func(m *Manifest) { m.Version = "verirelay-manifest-v1" }, "version"},
		{"verirelay repository", func(m *Manifest) { m.Source.VeriRelay.Repository = "https://github.com/verirelay/verirelay.git" }, "source.verirelay.repository"},
		{"veriforge repository", func(m *Manifest) { m.Source.VeriForge.Repository = "" }, "source.veriforge.repository"},
		{"verirelay commit", func(m *Manifest) { m.Source.VeriRelay.Commit = "main" }, "source.verirelay.commit"},
		{"veriforge commit", func(m *Manifest) { m.Source.VeriForge.Commit = strings.ToUpper(validCommit) }, "source.veriforge.commit"},
		{"launch profile version", func(m *Manifest) { m.LaunchProfile.Version = "verirelay-launch-profile-v1" }, "launch_profile.version"},
		{"measurement profile", func(m *Manifest) { m.LaunchProfile.MeasurementProfile = "sev-snp-qemu-direct-boot-v1" }, "launch_profile.measurement_profile"},
		{"vcpu type", func(m *Manifest) { m.LaunchProfile.VCPUType = "host" }, "launch_profile.vcpu_type"},
		{"guest features", func(m *Manifest) { m.LaunchProfile.GuestFeatures = "0x0" }, "launch_profile.guest_features"},
		{"kernel hashes", func(m *Manifest) { m.LaunchProfile.KernelHashes = false }, "launch_profile.kernel_hashes"},
		{"empty kernel append", func(m *Manifest) { m.LaunchProfile.KernelAppend = "" }, "launch_profile.kernel_append"},
		{"NUL in kernel append", func(m *Manifest) { m.LaunchProfile.KernelAppend = "a\x00b" }, "launch_profile.kernel_append"},
		{"newline in kernel append", func(m *Manifest) { m.LaunchProfile.KernelAppend = "a\nb" }, "launch_profile.kernel_append"},
		{"tab in kernel append", func(m *Manifest) { m.LaunchProfile.KernelAppend = "a\tb" }, "launch_profile.kernel_append"},
		{"DEL in kernel append", func(m *Manifest) { m.LaunchProfile.KernelAppend = "a\x7fb" }, "launch_profile.kernel_append"},
	} {
		manifest := validManifest()
		tc.mutate(&manifest)
		if err := manifest.Validate(); err == nil || !strings.HasPrefix(err.Error(), tc.detail) {
			t.Errorf("%s: err = %v, want prefix %q", tc.name, err, tc.detail)
		}
	}
}

func TestValidateCommitSHA(t *testing.T) {
	if err := ValidateCommitSHA(validCommit); err != nil {
		t.Fatal(err)
	}
	for _, commit := range []string{
		validCommit[:39],
		validCommit + "0",
		validCommit[:39] + "G",
		validCommit[:39] + "A",
		"main",
		"",
	} {
		if err := ValidateCommitSHA(commit); err == nil {
			t.Errorf("accepted %q", commit)
		}
	}
}

func TestValidateRepositoryURL(t *testing.T) {
	for _, raw := range []string{
		"https://github.com/verirelay/verirelay",
		"https://git.example.com:8443/team/repo",
		"https://example.com/a%2Fb",
	} {
		if err := ValidateRepositoryURL(raw); err != nil {
			t.Errorf("%q: %v", raw, err)
		}
	}
	for _, raw := range []string{
		"",
		"github.com/verirelay/verirelay",
		"http://github.com/verirelay/verirelay",
		"HTTPS://github.com/verirelay/verirelay",
		"ssh://git@github.com/verirelay/verirelay",
		"git@github.com:verirelay/verirelay",
		"https://token@github.com/verirelay/verirelay",
		"https://user:pass@github.com/verirelay/verirelay",
		"https://github.com/verirelay/verirelay?token=x",
		"https://github.com/verirelay/verirelay?",
		"https://github.com/verirelay/verirelay#main",
		"https://github.com/verirelay/verirelay#",
		"https://github.com/verirelay/verirelay/",
		"https://github.com/verirelay/verirelay.git",
		"https://github.com",
		"https://github.com/",
		"https://GitHub.com/verirelay/verirelay",
		"https://github.com/verirelay/veri relay",
		"https://github.com/verirelay/verirelay\n",
	} {
		if err := ValidateRepositoryURL(raw); err == nil {
			t.Errorf("accepted %q", raw)
		}
	}
}
