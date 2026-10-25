# MCPEnum

[![Go CI](https://github.com/capivara-research/MCPEnum/actions/workflows/ci.yml/badge.svg)](https://github.com/capivara-research/MCPEnum/actions/workflows/ci.yml)
[![MIT license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**MCP reconnaissance in one Go binary.** MCPEnum discovers HTTP-accessible [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) endpoints and inventories their advertised tools, resources, resource templates, and prompts. It records access and protocol evidence and highlights declarations for manual review.

> **Scope:** MCPEnum inventories HTTP-accessible MCP services without calling tools, reading resources, or running prompts. It supports Streamable HTTP and legacy HTTP+SSE; it does not launch stdio servers or verify vulnerabilities.

## Quick start

Download the archive for your platform from [Releases](https://github.com/capivara-research/MCPEnum/releases). Each release provides SHA-256 checksums and build provenance; [installation and verification steps](docs/RELEASES.md) cover Linux, macOS, and Windows.

To build from source, use Go 1.27.3 or newer. On Linux or macOS:

```sh
git clone https://github.com/capivara-research/MCPEnum.git
cd MCPEnum
go build -o mcpenum ./cmd/mcpenum
sudo install -m 0755 mcpenum /usr/local/bin/mcpenum
mcpenum --target 127.0.0.1:8000
```

Replace the example with a host and port in your authorized scope. You do not need to know the endpoint path: MCPEnum first checks the selected TCP port, confirms HTTP(S), then tests 17 MCP candidates. A `host:port` target checks only that port; a host without a port checks `80,443,3000,8000,8080,8443`. For an unknown port outside that list, use `--scan-ports START-END`.

For an endpoint you already know, use its exact URL. If the URL has no path, MCPEnum uses `/mcp`:

```sh
mcpenum --url https://mcp.example.test/api/mcp
```

Installing in `/usr/local/bin` lets you run `mcpenum` from any directory without `./`. If the shell cannot find it, check that `/usr/local/bin` is on `PATH`. The banner and progress go to `stderr`; the report goes to `stdout`. Use `--verbose` for request-level progress or `--format json` for machine-readable output.

Run `mcpenum --version` to identify the installed build when reporting a problem.

## Endpoint discovery

`--url` scans only the supplied URL. `--target` checks selected TCP ports, detects TLS on open ports, confirms HTTP(S), and then tests candidate paths on those ports. A `host:port` target uses that port only. `--scheme http` or `--scheme https` overrides protocol detection. An endpoint is confirmed through MCP protocol responses, not from HTTP 200 alone.

| Profile | Paths per selected port | Use |
|---|---:|---|
| `standard` | 9 | Faster check of common MCP and SSE paths. |
| `broad` (default) | 17 | Nmap’s 15 MCP candidates, `/api/v1/mcp`, and `/mcp/transport`. |
| `extensive` | 28 | Additional nested, versioned, and SSE paths. |

The candidate set is a curated list, not a protocol standard or an exhaustive search. It includes the paths in the pinned [`nmap-ai-recon` MCP library](https://github.com/insidetrust/nmap-ai-recon/blob/86e94bda9dbb1defc4aed61adb4b67b80e422c43/nselib/mcp.lua), `/api/v1/mcp` observed in FastMCP, and `/mcp/transport` from SecLists’ pinned [`mcp-server.txt`](https://github.com/danielmiessler/SecLists/blob/ab068333d7d44a9376e2037b0ed7d2e8ca5c6610/Discovery/Web-Content/mcp-server.txt). SecLists is not a runtime dependency. Candidate requests can create server logs; use only authorized targets and tune `--rate`, `--workers`, or time limits for larger scans.

Choose a profile or supply known paths:

```sh
mcpenum --target 10.0.0.5:8000 --path-profile standard
mcpenum --target 10.0.0.5 --ports 8000,8080 --path-profile extensive
mcpenum --target mcp.example.test:8443
mcpenum --target 10.0.0.5:8000 --path /tenant/team/mcp
# Unknown port: check the authorized TCP range before MCP paths
mcpenum --target 10.0.0.5 --scan-ports 1-65535 --verbose
```

For several custom paths, use `--paths-file`. Each nonblank line is one path; blank lines and lines beginning with `#` are ignored. Custom paths replace the built-in profile, and repeated `--path` values combine with the file. The limit is 128 paths, each up to 256 bytes.

```text
# paths.txt
/tenant/team/mcp
/api/custom-mcp
```

```sh
mcpenum --target 10.0.0.5:8000 --paths-file paths.txt
```

`--scan-ports` is opt in because checking all 65,535 TCP ports takes time and creates connection traffic. The default is 64 TCP workers with a 1,000 ms timeout and one retry for transient errors; adjust `--port-workers` and `--port-timeout-ms` to fit the network. It accepts host targets without an explicit port; the current implementation does not combine this mode with CIDR. MCPEnum does not discover arbitrary private prefixes. A negative result applies only to the selected ports and paths.

## Example output

This AI-RTA SecureCorp lab scan was captured on 25 October 2026 with `mcpenum --target 172.16.12.2 --scan-ports 7999-8001 --verbose --progress never`. The scanner found HTTP on port 8000, tested 17 paths on that port, and confirmed two MCP endpoints. The lines below are selected from the actual `stdout` and `stderr` output.

Selected output:

```text
PORT  172.16.12.2:8000: open
PORT  172.16.12.2:8001: connection_refused
PORT  172.16.12.2:7999: connection_refused
PORT  1/1 | http://172.16.12.2:8000: HTTP http

DISCOVERY SUMMARY  candidates: 17 | MCP endpoints: 2 | aliases: 0 | inconclusive: 2 | other: 13

PORT & HTTP
  Origin: http://172.16.12.2:8000 | TCP: open
  HEAD /: HTTP/1.1 405 Method Not Allowed
  OPTIONS /: HTTP/1.1 405 Method Not Allowed

TARGET  http://172.16.12.2:8000/mcp
Summary: MCP confirmed | anonymously listed tools: 4 (complete) | review leads: 2
  Endpoint: /mcp

TARGET  http://172.16.12.2:8000/mcp/messages
Summary: MCP confirmed | anonymously listed tools: 4 (complete) | review leads: 2
  Endpoint: /mcp/messages

INCONCLUSIVE CANDIDATES
  /sse      HTTP 200; no MCP confirmation
  /mcp/sse  HTTP 200; no MCP confirmation
```

The scan listed advertised tools but did not call them. HTTP 200 responses without MCP confirmation remain inconclusive. The order of `PORT` lines can vary because TCP checks run concurrently.

## Common commands

```sh
# Known endpoint
mcpenum --url https://mcp.example.test/mcp

# Host and port, endpoint unknown
mcpenum --target mcp.example.test:8000

# Scoped targets from a file; one URL, host, or host:port per line
mcpenum --targets-file scope.txt --workers 8 --rate 20

# Compare anonymous and Bearer-token inventories
mcpenum --url https://mcp.example.test/mcp --token-env MCPENUM_TOKEN

# JSON output and request-level trace
mcpenum --target mcp.example.test:8000 --format json --verbose
```

Set `MCPENUM_TOKEN` before the token example. The scanner checks anonymous access first, then repeats discovery and inventory with the Bearer token. Tokens and session ID values are not printed. `--token-file PATH` is also available.

`--targets-file` accepts blank lines and `#` comments. CIDR expansion requires `--allow-cidr` and is bounded by `--max-hosts`. The optional TCP range scan identifies open ports, but it is a bounded connect scan rather than a general service or OS fingerprinting replacement for Nmap.

## Options

| Option | Default | Purpose |
|---|---:|---|
| `--url URL` | — | Exact HTTP(S) MCP URL; repeatable. |
| `--target HOST[:PORT]` | — | Expand a host across selected ports and paths; repeatable. |
| `--targets-file FILE` | — | Read URLs, hosts, or host:port values, one per line. |
| `--ports LIST` | `80,443,3000,8000,8080,8443` | Selected ports or short ranges used with `--target`; at most 128 ports. |
| `--scan-ports START-END` | off | Discover open TCP ports in an authorized range before MCP path tests. |
| `--port-workers N` | `64` | Concurrent TCP checks in range discovery. |
| `--port-timeout-ms N` | `1000` | Per-port timeout; transient failures receive one retry. |
| `--scheme MODE` | `auto` | Detect TLS on open ports, or force `http` or `https` for `--target`. |
| `--path PATH` | Broad profile | Add a candidate path; repeatable. Custom paths replace the profile. |
| `--paths-file FILE` | — | Read paths; combines with `--path` and replaces the profile. |
| `--path-profile NAME` | `broad` | `standard` (9), `broad` (17), or `extensive` (28). |
| `--format FORMAT` | `text` | `text`, `json`, or `jsonl`. |
| `--color MODE` | `auto` | `auto`, `always`, or `never`; auto respects `NO_COLOR`. |
| `--schemas` | off | Include full tool input schemas in text output. |
| `--http-probe MODE` | `basic` | `off`, `basic` (`HEAD /`, `OPTIONS /`), or `extended` (also bounded `GET /`). `--target` still uses HTTP identification requests before MCP paths. |
| `--progress MODE` | `auto` | One progress line on `stderr`: `auto`, `always`, or `never`. |
| `--verbose` | off | Log candidate starts and protocol requests on `stderr`. |
| `--quiet` | off | Suppress banner and progress; cannot be combined with `--verbose`. |
| `--token-env NAME` | — | Read a Bearer token from an environment variable. |
| `--token-file FILE` | — | Read a Bearer token from a file. |
| `--timeout-ms N` | `5000` | Timeout per request. |
| `--budget-ms N` | `30000` | Time budget per endpoint. |
| `--workers N` | `8` | Maximum concurrent endpoint workers. |
| `--rate N` | `20` | Maximum HTTP requests per second; `0` disables pacing. |
| `--max-pages N` | `32` | Maximum pages per collection. |
| `--max-items N` | `5000` | Maximum items per collection. |
| `--max-body N` | `2097152` | Maximum response body size in bytes. |
| `--allow-cidr` | off | Enable CIDR expansion. |
| `--max-hosts N` | `16` | Maximum hosts expanded from a CIDR. |
| `--insecure` | off | Disable TLS certificate verification for controlled tests. |
| `--user-agent VALUE` | `MCPEnum/0.1.0` | Set the HTTP User-Agent. |

For the current flag list, run `mcpenum --help`; use `mcpenum --version` to identify the build.

## Reading results

MCPEnum keeps scan completion, MCP detection, authentication, and each inventory list separate.

| Result | Meaning |
|---|---|
| `scan_status: completed` | The scan finished; it does not mean MCP was found. |
| `detection.status: confirmed` | MCP responses were sufficient to confirm the endpoint. |
| `inconclusive` | The responses did not confirm MCP; inspect HTTP and protocol observations. |
| `complete` / `empty` | A list succeeded with items / with a valid empty result. |
| `unsupported` | The server returned method-not-found (`-32601`); this is not an empty list. |
| `partial` / `denied` / `timeout` / `error` | A limit, access restriction, time limit, or request failure affected that list. |

Server identity and versions are self-reported. Review leads are inferred from tool metadata and are not proof of exploitability. Tool listing does not establish that a tool can be called.

JSON always emits an array, including for one target. JSONL emits one result object per line. The schema version is `2.0`; [the CLI and JSON contract](docs/CLI-CONTRACT.md) defines field stability and exit codes. For the evidence model, see [How MCPEnum performs a scan](docs/TECHNICAL.md).

## Safety and limits

- The scanner sends bounded TCP checks, HTTP identification requests, and MCP discovery/list requests. A legacy handshake can create a server-side session.
- It does not send `tools/call`, `resources/read`, or `prompts/get`.
- TLS verification is enabled by default. Redirects remain on the original target origin.
- Use only systems in your authorized scope. Candidate requests may be recorded by the target.

MCPEnum inventories HTTP-accessible servers; it does not replace full network discovery, test vulnerabilities, execute payloads, or verify CVEs.

## Validation and development

The automated tests cover modern and legacy protocol behavior, pagination, authentication separation, malformed responses, output escaping, TCP/HTTP port filtering, and endpoint discovery. CI also checks pinned FastMCP 3.4.11 and 4.1.3 servers on a custom path. Manual interoperability checks cover Go, TypeScript, Python, and Rust MCP servers, including legacy SSE. See [validation details](docs/VALIDATION.md), the [support matrix](docs/SUPPORT.md), and the [technical scan flow](docs/TECHNICAL.md).

Run the project checks with:

```sh
go test ./...
go test -race ./...
go vet ./...
go build -o mcpenum ./cmd/mcpenum
```

For help, open a [GitHub issue](https://github.com/capivara-research/MCPEnum/issues) without including live credentials. Report security issues privately using [SECURITY.md](SECURITY.md). The project has no third-party Go runtime dependencies. See the [changelog](CHANGELOG.md), [contribution guide](CONTRIBUTING.md), and [license](LICENSE). Developed by [Fernando Viana (capivara-research)](https://github.com/capivara-research).
