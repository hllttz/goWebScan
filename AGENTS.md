# Repository Guidelines

## Project Structure & Module Organization

GoScan is a Go CLI network scanner. The executable entry point is in `cmd/goscan/main.go`. Internal implementation lives under `internal/`: `app` coordinates scans, `cli` parses flags and handles terminal behavior, `discovery` checks host liveness, `scanner` performs TCP connect scans, `service` identifies open services, `target` parses hosts and ports, `report` renders output, and `netutil` holds networking helpers. Public result types are in `pkg/goscan`. Design notes are in `docs/architecture.md`; generated release artifacts belong in `dist/`.

## Build, Test, and Development Commands

- `go run ./cmd/goscan scan 127.0.0.1 -Pn -p 22,80,443`: run the CLI from source against localhost.
- `go build -buildvcs=false -o goscan ./cmd/goscan`: build a local binary.
- `go test ./...`: run all unit tests.
- `go test ./internal/scanner -run TestName`: run a focused package test while iterating.
- `gofmt -w ./cmd ./internal ./pkg`: format Go source before committing.

Some tests open local TCP listeners. If a sandbox blocks sockets, rerun tests in a normal terminal.

## Coding Style & Naming Conventions

Use idiomatic Go formatted by `gofmt`; keep tabs for indentation as produced by the formatter. Package names should remain short, lowercase, and domain-specific. Prefer small interfaces around behavior that needs testing, especially network operations. Exported names in `pkg/goscan` need clear comments when they become part of the public API; keep implementation details inside `internal/`.

## Testing Guidelines

Tests use Go’s standard `testing` package and live beside source files as `*_test.go`. Name tests by behavior, for example `TestParsePortsRejectsInvalidRange` or `TestTCPConnectClassifiesRefused`. Favor deterministic tests with local listeners or fake dialers over external hosts. Run `go test ./...` before opening a pull request.

## Commit & Pull Request Guidelines

Recent commits use short imperative summaries such as `Enhance CLI scan options` and `Remove web frontend`. Follow that style: one concise subject, capitalized, no trailing period. Pull requests should describe the user-facing change, list test results, and note any scanner behavior changes, new flags, or output format changes. Link related issues when available and include sample CLI output for reporting or UX changes.

## Security & Configuration Tips

Only scan systems you own or are explicitly authorized to test. Do not add stealth, evasion, spoofing, or firewall-bypass behavior without explicit project direction. Avoid committing real scan targets, private network inventories, credentials, or generated reports containing sensitive hosts.
