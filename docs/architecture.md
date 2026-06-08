# GoScan Architecture

GoScan is a Go implementation of an nmap-like network scanner. The initial MVP focuses on:

- TCP Connect Scanner
- Host discovery
- Service identification

The design keeps privileged packet scanning, OS detection, scripting, and advanced evasion out of the first version, but leaves stable extension points for those capabilities.

## Goals

- Scan one or more hosts and ports using TCP connect.
- Discover whether hosts are likely alive before deeper scans.
- Identify common services from banners and lightweight probes.
- Provide predictable CLI output and machine-readable output.
- Keep scanner logic testable without requiring real network access.

## Non-Goals For MVP

- SYN scan or raw packet scanning.
- OS fingerprinting.
- UDP scanning.
- NSE-compatible scripting.
- Stealth, evasion, spoofing, or firewall bypass.
- Distributed scanning.

## Proposed Repository Layout

```text
goscan/
  cmd/
    goscan/
      main.go
  internal/
    app/
      app.go
      config.go
    cli/
      flags.go
      output.go
    discovery/
      discovery.go
      tcp_ping.go
      icmp.go
    scanner/
      scanner.go
      tcp_connect.go
      result.go
    service/
      identifier.go
      banner.go
      probes.go
      signatures.go
    target/
      parser.go
      ports.go
      target.go
    scheduler/
      scheduler.go
      rate_limit.go
      worker_pool.go
    report/
      report.go
      json.go
      text.go
    netutil/
      dialer.go
      resolver.go
      timeout.go
  pkg/
    goscan/
      types.go
  docs/
    architecture.md
  go.mod
```

### `cmd/goscan`

CLI entry point. It should only parse command-line arguments, create the application config, run the app, and return an exit code.

### `internal/app`

Application orchestration layer.

Responsibilities:

- Validate config.
- Parse targets and ports.
- Run host discovery.
- Run port scanning.
- Run service identification for open ports.
- Pass final results to report formatters.

### `internal/target`

Target and port parsing.

Supported MVP inputs:

- Single host: `scanme.nmap.org`
- IPv4 address: `192.168.1.10`
- CIDR: `192.168.1.0/24`
- Host list file, optional later.
- Ports:
  - single: `80`
  - list: `22,80,443`
  - range: `1-1024`
  - mixed: `22,80,8000-8100`

### `internal/discovery`

Host discovery determines whether a target should proceed to port scanning.

MVP strategy:

1. Resolve DNS names to IP addresses.
2. Try TCP connect probes against common ports.
3. Optionally support ICMP ping where permissions allow.

Default TCP discovery ports:

- `80`
- `443`
- `22`
- `3389`
- `445`

Discovery result states:

- `up`
- `down`
- `unknown`

If discovery is disabled, all targets are treated as `up`.

### `internal/scanner`

Port scanning engine.

MVP scanner:

- TCP Connect Scanner using `net.Dialer.DialContext`.
- No raw sockets required.
- Works without elevated privileges.

Port result states:

- `open`: TCP connection succeeded.
- `closed`: connection refused or actively rejected.
- `filtered`: timeout or unreachable network condition.
- `unknown`: unexpected error.

Scanner interface:

```go
type Scanner interface {
    Scan(ctx context.Context, target Target, port Port) (PortResult, error)
}
```

TCP connect implementation should classify errors carefully and avoid treating every error as closed.

### `internal/service`

Service identification runs only against open TCP ports.

MVP identification methods:

1. Static port hints, for example `80 -> http`, `22 -> ssh`.
2. Passive banner read after connect.
3. Lightweight protocol probes where safe:
   - HTTP: `HEAD / HTTP/1.0`
   - TLS detection by handshake attempt.
   - SSH banner read.
   - SMTP banner read.

Service result fields:

- service name
- product, if detected
- version, if detected
- confidence score
- raw banner, optionally truncated

The service package should expose a single identifier interface:

```go
type Identifier interface {
    Identify(ctx context.Context, target Target, port Port) (ServiceResult, error)
}
```

### `internal/scheduler`

Controls concurrency, timeout, cancellation, and rate limits.

MVP behavior:

- Fixed worker pool.
- Context cancellation support.
- Per-connection timeout.
- Global concurrency limit.
- Optional per-host concurrency limit.

The scheduler should not know scanner implementation details. It accepts jobs and emits results.

### `internal/report`

Output formatting.

MVP formats:

- Text table for humans.
- JSON for automation.

Suggested result shape:

```json
{
  "targets": [
    {
      "host": "scanme.nmap.org",
      "addresses": ["45.33.32.156"],
      "status": "up",
      "ports": [
        {
          "port": 22,
          "protocol": "tcp",
          "state": "open",
          "service": {
            "name": "ssh",
            "product": "OpenSSH",
            "version": "8.4",
            "confidence": 90
          }
        }
      ]
    }
  ]
}
```

### `internal/netutil`

Small wrappers around network operations.

Purpose:

- Make network calls mockable.
- Centralize timeout behavior.
- Keep scanner and service packages deterministic in tests.

## Core Data Model

```go
type Target struct {
    Input     string
    Hostname  string
    Addresses []net.IP
}

type Port struct {
    Number   uint16
    Protocol string
}

type HostStatus string

const (
    HostUp      HostStatus = "up"
    HostDown    HostStatus = "down"
    HostUnknown HostStatus = "unknown"
)

type PortState string

const (
    PortOpen     PortState = "open"
    PortClosed   PortState = "closed"
    PortFiltered PortState = "filtered"
    PortUnknown  PortState = "unknown"
)

type PortResult struct {
    Target   Target
    Port     Port
    State    PortState
    Latency  time.Duration
    Error    string
    Service  *ServiceResult
}

type ServiceResult struct {
    Name       string
    Product    string
    Version    string
    Confidence int
    Banner     string
}
```

## High-Level Flow

```text
CLI flags
  -> app.Config
  -> target parsing
  -> DNS resolution
  -> host discovery
  -> scan jobs for live hosts
  -> TCP connect scanner
  -> service identifier for open ports
  -> aggregate results
  -> report output
```

## CLI Design

Example commands:

```bash
goscan scan scanme.nmap.org -p 22,80,443
goscan scan 192.168.1.0/24 -p 1-1024 --timeout 2s --concurrency 200
goscan scan targets.txt -p top100 --json
goscan scan 10.0.0.1 --no-discovery
```

Initial flags:

- `-p, --ports`: port list, range, or preset.
- `--timeout`: per-connection timeout.
- `--concurrency`: max concurrent scan jobs.
- `--host-concurrency`: max concurrent jobs per host.
- `--no-discovery`: skip host discovery.
- `--json`: output JSON.
- `--service`: enable service identification, default true.
- `--banner-limit`: max banner bytes to store.

## TCP Connect Scanner Design

The TCP connect scanner opens a full TCP connection to each target port.

Algorithm:

1. Create a context with timeout.
2. Dial `tcp` address using `net.Dialer`.
3. If connection succeeds, close it and return `open`.
4. If error is connection refused, return `closed`.
5. If timeout, return `filtered`.
6. If network unreachable or host unreachable, return `filtered`.
7. Otherwise return `unknown`.

Pros:

- Portable.
- No root privileges.
- Easy to test.

Cons:

- Less stealthy than SYN scan.
- Completes full TCP handshake.
- Can be logged by services.

## Host Discovery Design

MVP should avoid requiring raw socket permissions.

Default discovery implementation:

- DNS resolution for hostnames.
- TCP connect probes against common ports.
- Mark host `up` when any probe succeeds or returns connection refused.
- Mark host `down` only when all probes strongly indicate unreachable.
- Mark host `unknown` on ambiguous timeout-heavy results.

Rationale:

- A refused TCP connection proves the host is reachable.
- A timeout does not prove the host is down because firewalls may drop packets.

## Service Identification Design

Service identification should be conservative. The first version should prefer a correct generic result over an overconfident specific result.

Strategy order:

1. Port hint gives baseline candidate.
2. Banner read may confirm service.
3. Protocol probe may refine product/version.
4. Confidence score communicates certainty.

Examples:

- Port `22`, banner starts with `SSH-2.0-OpenSSH_8.9`: `ssh`, `OpenSSH`, `8.9`, confidence `95`.
- Port `80`, HTTP response has `Server: nginx/1.24.0`: `http`, `nginx`, `1.24.0`, confidence `90`.
- Port `443`, TLS handshake succeeds: `https`, confidence `80`.

## Concurrency Model

Use worker pools and channels for MVP.

```text
job producer
  -> scan job channel
  -> N scan workers
  -> result channel
  -> aggregator
```

Rules:

- Every public operation accepts `context.Context`.
- Workers stop when context is canceled.
- Result aggregation is single-owner to avoid data races.
- Per-host concurrency can be added with a keyed semaphore.

## Error Handling

Errors should be classified into scan states when possible.

Fatal errors:

- invalid target
- invalid port expression
- invalid timeout
- unsupported output format

Per-target or per-port errors:

- DNS lookup failure
- connection refused
- timeout
- no route to host
- TLS handshake failure

Per-port errors should not stop the whole scan unless the context is canceled.

## Testing Strategy

Unit tests:

- port parser
- target parser
- TCP error classifier
- service banner parser
- report JSON shape

Integration tests:

- local TCP listener returns `open`
- unused localhost port returns `closed`
- local HTTP test server identifies `http`
- SSH-like test server returns SSH banner

Avoid tests that depend on external internet access.

## Security And Ethics Defaults

The tool should be designed for authorized scanning.

Default safeguards:

- Conservative concurrency default.
- Clear CLI warning in documentation.
- No stealth or evasion features in MVP.
- No automatic internet-wide target expansion.

## MVP Milestones

### Milestone 1: Project Skeleton

- `go.mod`
- CLI command
- config model
- text output placeholder

### Milestone 2: Target And Port Parsing

- parse hosts, IPv4, CIDR
- parse port expressions
- add tests

### Milestone 3: TCP Connect Scanner

- implement scanner interface
- classify common network errors
- add localhost integration tests

### Milestone 4: Host Discovery

- implement TCP discovery probes
- allow `--no-discovery`
- add tests with local listeners

### Milestone 5: Service Identification

- static port hints
- banner grabber
- HTTP, SSH, TLS basic detection
- add tests with local servers

### Milestone 6: Reporting

- text table
- JSON output
- stable result structs

## Future Extensions

- UDP scanner.
- SYN scanner with raw sockets.
- OS fingerprinting.
- traceroute.
- scan resume.
- top ports database.
- plugin or scripting engine.
- richer service probe signatures.
- HTML reports.
- distributed scan workers.
