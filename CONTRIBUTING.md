# Contributing

## Development setup

Go, at the version in `go.mod`.

## Checks

The pull request checks match CI (`.github/workflows/ci.yml`):

```bash
go run mvdan.cc/gofumpt@v0.12.0 -l .
go vet ./...
golangci-lint run   # use the version pinned in CI
go test ./...
go build ./...
go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.12
```

## Commit style

Use Conventional Commits (`feat:`, `fix:`, `docs:`, `chore:`).

## Wire-contract compatibility

Every format identifier has the form `name/N`, starting at 1, in a field named `version`.

Each format is decoded strictly (unknown fields rejected) or leniently (unknown fields ignored). Duplicate keys are rejected in both.

| Decoding | Formats |
| --- | --- |
| Strict | Receipt, Guest Manifest, Bootstrap |
| Lenient | Runtime Config, `veriprov/1` messages, attestation response, Receipt Evidence Bundle (its `receipt` is strict), Raw Capture envelope and plaintext |

New fields in a lenient format must be safe to ignore. Any change that tightens security or changes meaning bumps the version.

The golden vectors in `avr1/testdata/` and `veriprov1/testdata/` pin the wire format, so a golden change is a wire-format change. The JSON Schemas in `schemas/veriprov1/` change together with the `veriprov1` types.
