English | [简体中文](veriprov1.zh-CN.md)

# `veriprov/1` Provisioning

`veriprov/1` is the Provisioning contract between VeriProv (server) and the VeriRelay Guest (client).

[`schemas/veriprov1/`](../schemas/veriprov1/) holds JSON Schemas for the messages and the Runtime Config. The Go implementation is documented at [pkg.go.dev](https://pkg.go.dev/github.com/verirelay/protocol/veriprov1).

Every message and the Runtime Config is exactly one JSON object, decoded leniently:

- Unknown fields at any depth are ignored.
- Duplicate keys at any depth are invalid, and every key matches its field name exactly, including case.
- Required fields are required.

All base64url values are canonical and unpadded. Timestamps are RFC 3339 UTC with whole seconds and a `Z` suffix, such as `2026-07-11T07:00:00Z`.

## Challenge

The challenge request is the empty JSON object `{}`.

The challenge response has these fields, all required:

| Field | Type | Rule |
| --- | --- | --- |
| `challenge_id` | string | Opaque token: base64url of at least 16 bytes. |
| `nonce` | string | Base64url of exactly 32 bytes. |
| `issued_at` | string | Timestamp. |
| `expires_at` | string | Timestamp later than `issued_at`. |
| `ttl_seconds` | integer | Positive. |

The client sends `challenge_id` back unchanged. VeriProv alone decides whether a challenge is valid or expired. The client does not reject a challenge by its own clock.

## Provisioning

The provision request has these fields, all required:

| Field | Type | Rule |
| --- | --- | --- |
| `challenge_id` | string | `challenge_id` from the challenge response. |
| `provisioning_public_key` | string | Base64url raw 32-byte X25519 public key. The Runtime Config is sealed to it. |
| `attestation_report` | string | Base64url of the raw AMD SEV-SNP Attestation Report, 1184 bytes. Its `REPORT_DATA` is the key binding below. |

The provision response is `{"envelope": {...}}`, where the envelope has these fields, all required:

| Field | Type | Rule |
| --- | --- | --- |
| `version` | string | `"veriprov/1"`. |
| `challenge_id` | string | The request's `challenge_id`. |
| `enc` | string | Base64url 32-byte HPKE encapsulated key. |
| `ciphertext` | string | Base64url HPKE ciphertext. |
| `aad.protocol` | string | `"veriprov/1"`. |
| `aad.challenge_id` | string | Equal to the envelope's `challenge_id`. |
| `signature` | string | Base64url 64-byte Ed25519 signature. |

## Key binding

```text
REPORT_DATA = SHA-512( "veriprov/1" || 0x00 || nonce || provisioning_public_key )
```

`nonce` is the 32-byte challenge nonce and `provisioning_public_key` is the raw 32-byte X25519 public key.

## Sealing

```text
HPKE (RFC 9180), base mode, single-shot
suite = DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / ChaCha20-Poly1305
info  = "veriprov/1\x00runtime-config"
aad   = {"protocol":"veriprov/1","challenge_id":"<id>"}
```

The AAD bytes are that compact JSON: exactly these two members, in this order, with no whitespace. `<id>` is the envelope's `challenge_id`. The plaintext is the Runtime Config JSON.

## Envelope signature

```text
message   = "veriprov/1\x00envelope\x00" || challenge_id || 0x00 || enc || ciphertext
signature = Ed25519(VeriProv identity private key, message)
```

`challenge_id` is the envelope's `challenge_id` string, as sent, in UTF-8. `enc` and `ciphertext` are the decoded bytes.

The Guest verifies `signature` with the Bootstrap's `identity_public_key` ([Guest files](guest.md), section "Bootstrap") before it opens the envelope, and rejects the envelope if the signature does not verify.

## Errors

An error response body is `{"error": {...}}`:

| Field | Type | Rule |
| --- | --- | --- |
| `error.code` | string | One of the codes below. |
| `error.message` | string | Human-readable description. |
| `error.request_id` | string, optional | Request id. |

Each code has a fixed HTTP status:

| Code | HTTP status |
| --- | ---: |
| `invalid_request.malformed_json` | 400 |
| `invalid_request.invalid_field` | 400 |
| `invalid_request.body_too_large` | 413 |
| `challenge.not_found` | 404 |
| `challenge.expired` | 409 |
| `attestation.report_data_mismatch` | 409 |
| `policy.denied` | 409 |
| `envelope.hpke_failed` | 503 |
| `service.unavailable` | 503 |
| `internal.error` | 500 |

The service routes and the conditions behind each code are documented in [VeriProv Service API](https://github.com/verirelay/veriprov/blob/main/docs/api.md).

## Runtime Config

```json
{
  "version": "verirelay-runtime-config/1",
  "admin_token": "<token>",
  "receipt_store": { "type": "redis", "addr": "redis.internal:6379", "tls": true, "key_prefix": "verirelay:", "ttl_seconds": 3600 },
  "raw_store": { "type": "memory", "max_ttl_seconds": 86400, "max_bytes": 268435456 }
}
```

| Field | Type | Rule |
| --- | --- | --- |
| `version` | string | Required: `"verirelay-runtime-config/1"`. |
| `admin_token` | string | Required and non-empty, with no leading or trailing whitespace. |
| `receipt_store` | object | Optional. The Receipt store. |
| `raw_store` | object | Optional. The Raw Capture store. |

`receipt_store` and `raw_store` have these fields:

| Field | Applies to | Type | Rule |
| --- | --- | --- | --- |
| `type` | every store | string | Required: `"redis"` or `"memory"`. |
| `addr` | Redis | string | Required, not blank. |
| `tls` | Redis | boolean | Optional. |
| `username` | Redis | string | Optional. |
| `password` | Redis | string | Optional. |
| `db` | Redis | integer | Optional, not negative. |
| `key_prefix` | Redis | string | Optional, non-empty. Default `"verirelay:"`. |
| `ttl_seconds` | `receipt_store` | integer | Optional, positive. Default `3600`. |
| `max_entries` | memory `receipt_store` | integer | Optional, positive. Default `10000`. |
| `max_ttl_seconds` | `raw_store` | integer | Optional, not negative. `0` or absent means no cap. |
| `max_bytes` | memory `raw_store` | integer | Optional, positive. Default `268435456` (256 MiB). |

An absent field takes its default, and a present field must satisfy its rule. Fields that do not apply to a store's `type` are ignored.

When a store is absent:

- Without `receipt_store`, the Receipt store is a memory store with the defaults.
- Without `raw_store`, the Raw Capture store uses the Redis connection and `key_prefix` of a Redis `receipt_store`, and is otherwise a memory store with the defaults.

`key_prefix` is the namespace root of every Redis key:

| Key | Content |
| --- | --- |
| `<key_prefix>receipt:<request_id>` | A Receipt. |
| `<key_prefix>attestation:<key_id>` | The archived attestation response for a Receipt Signing Key. |
| `<key_prefix>raw:<store_id>` | A Raw Capture. |

What each field does is described in VeriRelay's [configuration.md](https://github.com/verirelay/verirelay/blob/main/docs/configuration.md), section "Runtime Config from VeriProv".

## Test vectors

| File | Content |
| --- | --- |
| [`veriprov1/testdata/binding_golden.json`](../veriprov1/testdata/binding_golden.json) | A nonce, an X25519 public key, the binding input, and the resulting `REPORT_DATA`. |
| [`veriprov1/testdata/hpke_golden.json`](../veriprov1/testdata/hpke_golden.json) | A test-only recipient key pair, an AAD context, `enc`, `ciphertext`, and the plaintext they open to. |
| [`veriprov1/testdata/envelope_signature_golden.json`](../veriprov1/testdata/envelope_signature_golden.json) | A test-only VeriProv Identity Key seed and public key, a signed envelope, and its signature message. |
| [`veriprov1/testdata/verirelay_runtime_config_valid.json`](../veriprov1/testdata/verirelay_runtime_config_valid.json) | A valid Runtime Config. |
