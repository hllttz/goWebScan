# goWebScan

goWebScan is a Go-based network scanner inspired by nmap. The current focus is a practical CLI scanner with TCP connect scanning, host discovery, service detection, progress output, and graceful cancellation.

> Use this tool only on systems and networks you own or are explicitly authorized to test.

## Features

- TCP Connect Scanner, no raw socket privileges required.
- Host discovery with TCP probes.
- Port states: `open`, `closed`, `filtered`, `unreachable`, `unknown`.
- `reason` field explains why each state was assigned.
- CIDR, multi-target, and target file input.
- Port expressions such as `22`, `22,80,443`, `1-1024`, and `22,80,8000-8080`.
- `-Pn` to skip host discovery.
- `-sV` active service detection.
- CLI progress display.
- Ctrl+C graceful cancellation with partial results.
- Text output similar to nmap and JSON output for automation.
- Optional React/Web API prototype kept in `web/` and `cmd/goscan-web/`.

## Quick Start

Run from source:

```bash
go run ./cmd/goscan scan 127.0.0.1 -Pn -p 22,80,443
```

Build the CLI:

```bash
go build -buildvcs=false -o goscan ./cmd/goscan
./goscan scan 127.0.0.1 -Pn -p 22,80,443
```

## CLI Usage

```bash
goscan scan <target...> [flags]
```

Common flags:

```text
-p, --ports          Ports to scan, for example 22,80,443 or 1-1024
-Pn                  Skip host discovery
-sV                  Enable active service version detection
--timeout            Per-connection timeout
--host-workers       Maximum concurrent target hosts
--port-workers       Maximum concurrent port scans per host
--json               Write JSON output
--banner-limit       Maximum banner bytes to keep
```

Examples:

```bash
# Scan localhost common ports
goscan scan 127.0.0.1 -Pn -p 22,80,443

# Scan a CIDR
goscan scan 192.168.1.0/24 -p 22,80,443 --host-workers 20 --port-workers 200

# Enable service detection
goscan scan 127.0.0.1 -Pn -p 22,80,443,8080 -sV

# JSON output
goscan scan 127.0.0.1 -Pn -p 1-1024 --json

# Target file
goscan scan targets.txt -p 22,80,443
```

## Example Text Output

```text
Starting GoScan: 1 target(s), 3 port(s), 3 total probe(s)
Progress: 3/3 probes complete (100%)
Host complete: 127.0.0.1 status=up ports=3 (1 done)
Elapsed: 0s
Starting GoScan 0.1 at 2026-06-08 14:11 CST
GoScan scan report for 127.0.0.1 (127.0.0.1)
Host is up (discovery_skipped).
PORT      STATE        SERVICE       VERSION            REASON
22/tcp    closed       -             -                  connection_refused
80/tcp    closed       -             -                  connection_refused
443/tcp   closed       -             -                  connection_refused
Port summary: 0 open, 3 closed, 0 filtered, 0 unreachable, 0 unknown

GoScan done: 1 IP address(es) scanned
```

## Service Detection

`-sV` performs lightweight active service detection. It currently includes:

- HTTP and HTTPS detection.
- SSH banner parsing.
- FTP, SMTP, POP3, IMAP banner signatures.
- MySQL, PostgreSQL, VNC, Redis, and memcached signatures.
- Redis PING probe.
- HTTP probe fallback for non-standard ports.

This is intentionally conservative and lightweight. It is not NSE-compatible and does not try to bypass firewalls or IDS systems.

## Release Builds

Local release artifacts are generated as:

```text
dist/goscan-v0.1.0-linux-amd64.tar.gz
dist/goscan-v0.1.0-windows-amd64.zip
dist/checksums.txt
```

Manual cross-compilation:

```bash
GOOS=linux GOARCH=amd64 go build -buildvcs=false -trimpath -ldflags="-s -w" -o dist/goscan-linux-amd64 ./cmd/goscan
GOOS=windows GOARCH=amd64 go build -buildvcs=false -trimpath -ldflags="-s -w" -o dist/goscan-windows-amd64.exe ./cmd/goscan
```

## Development

Run tests:

```bash
go test ./...
```

Some tests open local TCP listeners. If your sandbox blocks local sockets, run tests in a normal terminal.

Build the optional frontend prototype:

```bash
cd web
npm install
npm run build
```

Run the optional Web API:

```bash
go run ./cmd/goscan-web
```

Run the optional frontend dev server:

```bash
cd web
npm run dev
```

## Project Layout

```text
cmd/goscan          CLI entry point
cmd/goscan-web      Optional Web API
internal/app        Scan orchestration
internal/cli        CLI flags, progress, Ctrl+C handling
internal/discovery  Host discovery
internal/scanner    TCP connect scanner and state classification
internal/service    Service detection
internal/report     Text and JSON output
internal/target     Target and port parsing
pkg/goscan          Shared result types
web                 Optional React frontend prototype
```

## License

No license has been selected yet.
