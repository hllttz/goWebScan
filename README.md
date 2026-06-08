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
- Full TCP port scans with `-p-`.
- Top port presets with `top100` or `--top-ports N`.
- Exclude ports with `--exclude-ports`.
- `-Pn` to skip host discovery.
- `-sV` active service detection.
- `--open` to show only open ports.
- CLI progress display.
- Ctrl+C graceful cancellation with partial results.
- Text output similar to nmap, JSON output, CSV output, and output files.

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
-p-                  Scan all TCP ports, 1-65535
--top-ports N        Scan the N most common TCP ports
--exclude-ports      Exclude ports, for example 25,137-139
-Pn                  Skip host discovery
-sV                  Enable active service version detection
--open               Show only open ports in output
--timeout            Per-connection timeout
--host-workers       Maximum concurrent target hosts
--port-workers       Maximum concurrent port scans per host
--json               Write JSON output
-oT                  Write normal text output to file
-oJ                  Write JSON output to file
-oC                  Write CSV output to file
--silent             Suppress progress output
--verbose            More frequent progress output
--no-color           Disable colored output
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

# Full TCP port scan, output only open ports
goscan scan 127.0.0.1 -Pn -p- --open

# Scan top 100 ports, excluding noisy ports
goscan scan 192.168.1.10 --top-ports 100 --exclude-ports 25,137-139

# Write multiple output formats
goscan scan 127.0.0.1 -Pn -p 22,80,443 -oT scan.txt -oJ scan.json -oC scan.csv

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

## Module

```text
github.com/hllttz/goWebScan
```

## Development

Run tests:

```bash
go test ./...
```

Some tests open local TCP listeners. If your sandbox blocks local sockets, run tests in a normal terminal.

## Project Layout

```text
cmd/goscan          CLI entry point
internal/app        Scan orchestration
internal/cli        CLI flags, progress, Ctrl+C handling
internal/discovery  Host discovery
internal/scanner    TCP connect scanner and state classification
internal/service    Service detection
internal/report     Text and JSON output
internal/target     Target and port parsing
pkg/goscan          Shared result types
```

## License

No license has been selected yet.
