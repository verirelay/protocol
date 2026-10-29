English | [简体中文](avr1.zh-CN.md)

# `avr/1` Receipts

`avr/1` is the Receipt format VeriRelay issues for every complete Upstream forward: a canonical, Ed25519-signed record of the exchange whose signing key is bound to the Attestation Report. The Go implementation is documented at [pkg.go.dev](https://pkg.go.dev/github.com/verirelay/protocol/avr1).

All base64url values are canonical and unpadded, and all hex values are lowercase.

## Decoding

| Format | Decoding |
| --- | --- |
| Receipt | Strict: unknown fields at any depth are invalid. |
| Attestation response | Lenient: unknown fields at any depth are ignored. |
| Receipt Evidence Bundle | Lenient, except that its `receipt` is strict. |
| Raw Capture envelope and plaintext | Lenient. |

Each value is exactly one JSON object. In every format:

- Duplicate keys at any depth are invalid.
- Every key matches its field name exactly, including case.
- Required fields are required.

## Receipt fields

| Field | Type | Meaning |
| --- | --- | --- |
| `version` | string | Always `"avr/1"`. |
| `canonicalization` | string | Always `"jcs-rfc8785"` (RFC 8785). |
| `signature_algorithm` | string | Always `"ed25519"`. |
| `hash_algorithm` | string | Always `"sha256"`. |
| `request_id` | string | VeriRelay-assigned request id (`X-VeriRelay-Request-Id`). |
| `timestamp` | string | RFC 3339 UTC, with a `Z` suffix. |
| `method` | string | Proxied request method. |
| `upstream_authority` | string | Upstream host[:port]. |
| `upstream_path` | string | Path and query as forwarded. |
| `request_body_sha256` | string | Hex SHA-256 of the request body. |
| `response_body_sha256` | string | Hex SHA-256 of the response body. |
| `response_status` | integer | Upstream HTTP status, from 100 to 599. |
| `upstream_tls.sni` | string | TLS SNI used for the Upstream. |
| `upstream_tls.spki_sha256` | string | Hex SHA-256 of the Upstream certificate SPKI. |
| `service_public_key` | string | Base64url raw 32-byte Ed25519 public key of the Receipt Signing Key. |
| `key_id` | string | Hex of the first 8 bytes of SHA-256(raw public key). |
| `signature.payload_sha256` | string | Hex SHA-256 of the signed payload. |
| `signature.value` | string | Base64url 64-byte Ed25519 signature over the payload. |

Every field is required, and required strings are non-empty.

## Signature

The signer builds the payload and signs it:

1. Remove `signature` from the Receipt object.
2. Canonicalize the rest with JCS (RFC 8785). The result is the payload.
3. Set `signature.payload_sha256` to the hex SHA-256 of the payload and `signature.value` to the Ed25519 signature over the payload bytes.

A verifier accepts a Receipt only if all of these hold:

- It decodes strictly: no fields other than those listed above, including inside `upstream_tls` and `signature`, and no duplicate keys.
- Every field is present, and the four algorithm identifiers have exactly the values listed above.
- `request_body_sha256`, `response_body_sha256`, and `upstream_tls.spki_sha256` are 64 hex characters.
- `response_status` is an integer from 100 to 599.
- `service_public_key` decodes to 32 bytes and `key_id` matches it.
- `timestamp` parses as RFC 3339 and ends in `Z`.
- `signature.payload_sha256` matches the recomputed payload, and `signature.value` verifies under `service_public_key`.

## Key binding

```text
REPORT_DATA = SHA-512(
    "VeriRelay-AVR-REPORT-DATA/1\x00"
    || u32be(len("avr/1"))   || "avr/1"
    || u32be(len("ed25519")) || "ed25519"
    || u32be(32) || receipt_signing_public_key
    || u32be(32) || nonce
)
```

- `u32be(n)` is `n` as a 4-byte big-endian integer.
- `receipt_signing_public_key` is the raw 32-byte Ed25519 public key.
- `nonce` is the 32-byte Attestation Nonce.

## Attestation response

The body of `GET /v1/avr/attestation?nonce=<base64url>` is one JSON object. The nonce is 32 bytes.

The fields are claims: a verifier checks identifier values, encodings, certificate trust, signatures, freshness, policy, and disclosure claims itself.

| Field | Type | Meaning |
| --- | --- | --- |
| `version` | string | `"avr/1"`. |
| `tee_type` | string | `"sev-snp"`. |
| `evidence` | object | Attestation Evidence. |
| `endorsements` | object | AMD certificate chain. |
| `nonce` | string | Base64url Attestation Nonce. |
| `receipt_signing_public_key` | string | Base64url raw 32-byte Ed25519 public key of the Receipt Signing Key. |
| `key_id` | string | `key_id` of that public key, computed as in the Receipt. |
| `key_binding` | object | The key binding parameters. |
| `source` | object | `verirelay` and `veriforge`, each an object with `repository` and `commit` strings. |
| `launch_profile` | object | Strings `version`, `measurement_profile`, `vcpu_type`, `guest_features`, `kernel_append`; boolean `kernel_hashes`. |
| `bootstrap` | string, optional | Base64url of the exact Bootstrap file bytes. Absent in development mode. |

`evidence`:

| Field | Type | Meaning |
| --- | --- | --- |
| `format` | string | `"amd-sev-snp-report/1"`. |
| `report` | string | Base64url of the raw AMD SEV-SNP Attestation Report, 1184 bytes. |
| `report_data` | string | Hex `REPORT_DATA`. |

`endorsements` carries certificates as base64url of their DER bytes:

| Field | Type | Meaning |
| --- | --- | --- |
| `format` | string | `"amd-sev-snp-cert-chain/1"`. |
| `encoding` | string | `"base64url-der"`. |
| `vcek` | string, optional | VCEK certificate. Omitted when empty. |
| `vlek` | string, optional | VLEK certificate. Omitted when empty. |
| `ask` | string | ASK certificate. |
| `ark` | string | ARK certificate. |

`key_binding`:

| Field | Value |
| --- | --- |
| `rule` | `"verirelay-avr-report-data/1"`, the key binding above |
| `protocol_version` | `"avr/1"` |
| `signature_algorithm` | `"ed25519"` |
| `report_data_sha512` | Hex `REPORT_DATA` computed from `receipt_signing_public_key` and `nonce` |
| `report_data_encoding` | `"raw-64-bytes"` |
| `public_key_encoding` | `"base64url-unpadded-ed25519-raw-32-bytes"` |
| `nonce_encoding` | `"base64url-unpadded-raw-32-bytes"` |

The `source` and `launch_profile` disclosures come from the [Guest Manifest](guest.md) but are not a full Guest Manifest. Their presence alone does not authenticate source identity or release policy.

A verifier checks `bootstrap` against the Attestation Report: SHA-256 of the decoded `bootstrap` equals the report's `HOST_DATA` ([Guest files](guest.md), section "Bootstrap").

## Receipt Evidence Bundle

The Receipt Evidence Bundle, the body of `GET /v1/avr/evidence/<request_id>`, is a Receipt together with the archived attestation response for its Receipt Signing Key.

| Field | Type | Meaning |
| --- | --- | --- |
| `version` | string | `"avr/1"`. |
| `receipt` | object | The Receipt, decoded strictly. |
| `attestation` | object or null | The archived attestation response, or `null` when none is archived. |

## Raw Capture

A Raw Capture stores the exact request and response bodies of one exchange, encrypted with a per-capture key. The key is the 32-byte AES-256 key a client receives as `X-VeriRelay-Store-Key` (unpadded base64url). `store_id` is the `X-VeriRelay-Store-Id` value.

See VeriRelay's [api.md](https://github.com/verirelay/verirelay/blob/main/docs/api.md), section "Raw Capture".

The envelope:

| Field | Type | Meaning |
| --- | --- | --- |
| `version` | string | `"verirelay-raw-capture/1"`. |
| `algorithm` | string | `"AES-256-GCM"`. |
| `nonce` | string | Base64url 12-byte GCM nonce. |
| `ciphertext` | string | Base64url AES-256-GCM ciphertext and tag of the plaintext. |

The AAD is the UTF-8 string `version + ":" + store_id`, such as `verirelay-raw-capture/1:<store_id>`.

The plaintext is a JSON object:

| Field | Type | Meaning |
| --- | --- | --- |
| `version` | string | `"verirelay-raw-capture-plaintext/1"`. |
| `request_body` | string | Base64url of the exact request body bytes. |
| `response_body` | string | Base64url of the exact response body bytes. |

## Test vectors

| File | Content |
| --- | --- |
| [`avr1/testdata/avr1_signed_receipt_golden.json`](../avr1/testdata/avr1_signed_receipt_golden.json) | A signed Receipt, the same Receipt with reordered fields, its canonical payload, payload hash and signature, and negative cases. |
| [`avr1/testdata/avr1_attestation_with_bootstrap.json`](../avr1/testdata/avr1_attestation_with_bootstrap.json) | An attestation response with `bootstrap`. |
| [`avr1/testdata/avr1_attestation_without_bootstrap.json`](../avr1/testdata/avr1_attestation_without_bootstrap.json) | The same response without `bootstrap`. |
| [`avr1/testdata/raw_capture_golden.json`](../avr1/testdata/raw_capture_golden.json) | A test-only key, `store_id`, bodies, plaintext, AAD, and the Raw Capture envelope they produce. |

The attestation responses contain synthetic Attestation Evidence, not trusted Attestation Reports. See the [testdata README](../avr1/testdata/README.md).
