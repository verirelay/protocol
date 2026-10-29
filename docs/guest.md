English | [简体中文](guest.zh-CN.md)

# Guest files

The Go implementation is documented at [pkg.go.dev](https://pkg.go.dev/github.com/verirelay/protocol/guest).

The Guest Manifest and the Bootstrap are decoded strictly:

- Each is exactly one JSON object.
- Unknown fields and duplicate keys at any depth are invalid.
- Every key matches its field name exactly, including case.

Base64url values are canonical and unpadded.

## Guest Manifest

`/etc/verirelay/manifest.json` in the initrd records the Guest's build sources and launch parameters:

```json
{
  "version": "verirelay-guest-manifest/1",
  "source": {
    "verirelay": { "repository": "https://github.com/verirelay/verirelay", "commit": "<40-hex sha>" },
    "veriforge": { "repository": "https://github.com/verirelay/veriforge", "commit": "<40-hex sha>" }
  },
  "launch_profile": {
    "version": "verirelay-launch-profile/1",
    "measurement_profile": "sev-snp-qemu-direct-boot/1",
    "vcpu_type": "EPYC-v4",
    "guest_features": "0x1",
    "kernel_hashes": true,
    "kernel_append": "<kernel cmdline>"
  }
}
```

| Field | Rule |
| --- | --- |
| `version` | `"verirelay-guest-manifest/1"`. |
| `source.verirelay.repository`, `source.veriforge.repository` | Canonical HTTPS repository URL, described below. |
| `source.verirelay.commit`, `source.veriforge.commit` | Lowercase 40-hex commit SHA. |
| `launch_profile.version` | `"verirelay-launch-profile/1"`. |
| `launch_profile.measurement_profile` | `"sev-snp-qemu-direct-boot/1"`. |
| `launch_profile.vcpu_type` | `"EPYC-v4"`. |
| `launch_profile.guest_features` | `"0x1"`. |
| `launch_profile.kernel_hashes` | `true`. |
| `launch_profile.kernel_append` | Non-empty kernel cmdline with no NUL, newline, or other control characters. |

A repository URL:

- is an `https` URL with a host and a path;
- has no user info, query, fragment, or trailing slash;
- does not end in `.git`;
- is in canonical form: the scheme and host are lowercase, and every character that URL syntax requires to be percent-encoded is.

The Guest Manifest has no vCPU count: the Launch Measurement covers it, and one Boot Artifact Set boots with any vCPU count.

`source` and `launch_profile` are reproduction hints for recomputing the Launch Measurement. They are disclosed by the VeriRelay Attestation endpoint and kept outside `REPORT_DATA`, the key binding, and Receipts.

`launch_profile.kernel_append` is the authoritative kernel cmdline hint.

## Bootstrap

```json
{"version":"veriprov-bootstrap/1","protocol":"veriprov/1","url":"https://veriprov.example.com","identity_public_key":"<unpadded base64url, 32 bytes>","profile":"<optional>"}
```

| Field | Rule |
| --- | --- |
| `version` | `"veriprov-bootstrap/1"`. |
| `protocol` | `"veriprov/1"`. |
| `url` | HTTPS origin of VeriProv, with no user info, path (not even `/`), query, or fragment. An explicit port is allowed. |
| `identity_public_key` | Base64url of the 32-byte Ed25519 public key of the VeriProv Identity Key, which signs the envelope; see [`veriprov/1` Provisioning](veriprov1.md), section "Envelope signature". |
| `profile` | Optional. 1 to 64 characters of `[A-Za-z0-9._-]`; when present, it is not empty. |

The Bootstrap file is at most 4096 bytes and contains no NUL byte. `HOST_DATA` covers its exact bytes, so any change to the file, including whitespace, changes `HOST_DATA`.

### Config Disk

The host delivers the Bootstrap on the Config Disk, a read-only raw virtio block device:

- The device content is the Bootstrap bytes followed by zero padding to the end of the device.
- The CVM has exactly one virtio block device.
- The Guest takes the bytes before the first NUL as the Bootstrap. The device must contain a NUL after the Bootstrap, and the Bootstrap must not be empty.

### `HOST_DATA` binding

```text
HOST_DATA = SHA-256(Bootstrap file bytes)
```

The host sets `HOST_DATA` at launch with QEMU `-object sev-snp-guest,...,host-data=<base64 of the 32-byte digest>`.

The Guest compares SHA-256 of the Bootstrap it read with `HOST_DATA` in its own Attestation Report and does not provision on a mismatch.

VeriRelay discloses the Bootstrap bytes in its attestation response as `bootstrap` ([`avr/1` Receipts](avr1.md), section "Attestation response"), so a verifier checks the same equality.
