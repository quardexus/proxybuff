# Contributing to ProxyBuff

Thanks for your interest in improving ProxyBuff! This document explains how to build,
test and submit changes.

## Prerequisites

- [Go](https://go.dev/dl/) **1.24** or newer.
- (Optional) `make` and Docker for the convenience targets.

## Build & test

```bash
make build      # build ./bin/proxybuff
make test       # go test ./...
make test-race  # go test -race ./...
make lint       # gofmt check + go vet
make fmt        # gofmt -w
```

Without `make`:

```bash
go build ./...
go test ./...
go vet ./...
gofmt -l .      # must print nothing
```

## Code style

- All code must be `gofmt`-clean and pass `go vet`. CI enforces both.
- Keep changes focused and minimal; match the surrounding style and naming.
- Add or update tests for any behavior change. Pure logic (parsing, matching, key
  derivation, cacheability) should have table-driven unit tests.
- Prefer the standard library; new third-party dependencies need a good reason.

## Commit & pull requests

- Write clear, imperative commit subjects (e.g. `Add per-host TTL override`).
- One logical change per pull request; describe the motivation and any trade-offs.
- Update `CHANGELOG.md` (the `[Unreleased]`/next-version section) and relevant docs.
- Make sure `make lint test` is green before opening the PR.

## Security

Please **do not** open public issues for vulnerabilities — see [SECURITY.md](SECURITY.md)
for private disclosure.

## License

By contributing, you agree that your contributions are licensed under the
[Apache-2.0](LICENSE) license.
