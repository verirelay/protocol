# Attestation response fixtures

`avr1_attestation_with_bootstrap.json` and `avr1_attestation_without_bootstrap.json` are attestation response bodies, including the final newline, captured from VeriRelay's `GET /v1/avr/attestation` route. Both share the Attestation Nonce, Receipt Signing Key, Attestation Report, certificate chain, and Guest Manifest disclosure; only the `bootstrap` disclosure differs.

Their contents are synthetic:

- The Attestation Report is a version 3 Milan report signed by go-sev-guest's test-only certificate chain, with `REPORT_DATA` set to the key binding of the nonce and Receipt Signing Key, and `HOST_DATA` set to the SHA-256 of the disclosed Bootstrap.
- The Bootstrap names the test-only VeriProv Identity Key of [`veriprov1/testdata/envelope_signature_golden.json`](../../veriprov1/testdata/envelope_signature_golden.json).
- The endorsements are go-sev-guest's test-only certificate chain, and the disclosed Guest Manifest is a test manifest.

These vectors describe the wire format. Their report verifies only against the test-only AMD root, never against AMD's real roots. The tests decode them and byte-compare the re-encoded responses, including field order and omissions.
