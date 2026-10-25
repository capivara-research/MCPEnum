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

Replace the example with a host and port in your authorized scope. You do not need to know the endpoint path: MCPEnum checks the selected TCP port, confirms HTTP(S), then tests 17 MCP candidates. With `--target HOST` and no port, it checks TCP ports 1–65535 by default and tests MCP paths on every HTTP(S) port found. This full scan can take several minutes; use `HOST:PORT`, `--ports`, or `--scan-ports` to limit it.

For an endpoint you already know, use its exact URL. If the URL has no path, MCPEnum uses `/mcp`:

```sh
mcpenum --url https://mcp.example.test/api/mcp
```

Installing in `/usr/local/bin` lets you run `mcpenum` from any directory without `./`. If the shell cannot find it, check that `/usr/local/bin` is on `PATH`. The banner and progress go to `stderr`; the report goes to `stdout`. Use `--verbose` for request-level progress or `--format json` for machine-readable output.

Run `mcpenum --version` to identify the installed build when reporting a problem.

## Endpoint discovery

`--url` scans only the supplied URL. `--target HOST` first discovers open TCP ports, detects TLS, confirms HTTP(S), and then tests candidate paths on each HTTP(S) port. `HOST:PORT` limits discovery to one port. `--ports` selects specific ports, and `--scan-ports START-END` selects a range. `--no-port-scan` sends MCP candidate requests directly to an explicitly selected port; when using it on a nonstandard TLS port, supply `--scheme https`. An endpoint is confirmed through MCP protocol responses, not from HTTP 200 alone.

| What you know | Command | Network work |
|---|---|---|
| Host only | `mcpenum --target 10.0.0.5` | Check ports 1–65535, identify HTTP(S), test MCP paths. |
| Port known | `mcpenum --target 10.0.0.5:8000` | Check one port, identify HTTP(S), test MCP paths. |
| Selected ports | `mcpenum --target 10.0.0.5 --ports 8000,8443` | Check only those ports, then test HTTP(S) paths. |
| HTTP service known; skip checks | `mcpenum --target 10.0.0.5:8000 --no-port-scan` | Test MCP paths directly on that port. |
| Endpoint known | `mcpenum --url http://10.0.0.5:8000/mcp` | Test only that URL; no port discovery or path guessing. |

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
# Narrow the TCP range when appropriate
mcpenum --target 10.0.0.5 --scan-ports 7900-8100 --verbose
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

The full scan is the default for a bare host. It uses 256 TCP workers, up to 500 connections per second, an initial 300 ms attempt, and one retry up to 1,000 ms for transient errors. Adjust `--port-workers`, `--port-rate`, and `--port-timeout-ms` to fit the network. CIDR expansion still requires `--allow-cidr` and is bounded by `--max-hosts`; a full range across many hosts can take a long time. MCPEnum does not discover arbitrary private prefixes. A negative result applies only to the ports and paths tested.

Some HTTP servers close `HEAD /` and `OPTIONS /` without returning an HTTP response. If you already know such a service's port, use `--target HOST:PORT --no-port-scan` to test MCP paths directly; add `--scheme https` when that port uses TLS. Use `--url` when the endpoint path is known too.

## Example output

This AI-RTA SecureCorp lab scan was captured on 25 October 2026 with a source build. The command used `timeout 600 ./mcpenum --target 172.16.12.2 --verbose --progress never --format text`, with `stdout` and `stderr` redirected to separate files. With an installed binary, use `mcpenum` in place of `./mcpenum`. The scanner checked ports 1–65535, found open TCP on 22 and 8000, confirmed HTTP on 8000, and tested 17 MCP paths there. The lines below are selected from the actual output.

Selected output:

```text
PORT  172.16.12.2:22: open
PORT  172.16.12.2:8000: open
PORTS  65535/65535 checked
PORT  1/2 | http://172.16.12.2:22: open, HTTP unconfirmed
PORT  2/2 | http://172.16.12.2:8000: HTTP http

DISCOVERY SUMMARY  candidates: 18 | MCP endpoints: 2 | aliases: 0 | inconclusive: 2 | other: 14

HTTP PORTS
  http://172.16.12.2:8000  MCP: /mcp, /mcp/messages

PORT & HTTP
  Origin: http://172.16.12.2:8000 | TCP: open
  HEAD /: timeout
  OPTIONS /: HTTP/1.1 405 Method Not Allowed

TARGET  http://172.16.12.2:8000/mcp
Summary: MCP confirmed | anonymously listed tools: 4 (complete) | review leads: 2
  Endpoint: /mcp

TARGET  http://172.16.12.2:8000/mcp/messages
Summary: MCP confirmed | anonymously listed tools: 4 (complete) | review leads: 2
  Endpoint: /mcp/messages

```

The scan listed advertised tools but did not call them. HTTP 200 responses without MCP confirmation remain inconclusive. The order of `PORT` lines can vary because TCP checks run concurrently. The full report also shows every other candidate and the TCP-open port where HTTP was not confirmed.

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

`--targets-file` accepts blank lines and `#` comments. CIDR expansion requires `--allow-cidr` and is bounded by `--max-hosts`. The TCP discovery is a bounded connect scan rather than a general service or OS fingerprinting replacement for Nmap.

## Options

| Option | Default | Purpose |
|---|---:|---|
| `--url URL` | — | Exact HTTP(S) MCP URL; repeatable. |
| `--target HOST[:PORT]` | — | Expand a host across selected ports and paths; repeatable. |
| `--targets-file FILE` | — | Read URLs, hosts, or host:port values, one per line. |
| `--ports LIST` | unset | Limit a bare host to selected ports or short ranges; at most 128 ports. |
| `--scan-ports START-END` | `1-65535` for a bare host | Override the TCP discovery range. |
| `--no-port-scan` | off | Skip TCP/HTTP identification and test MCP paths directly; supply `HOST:PORT` or `--ports`. |
| `--port-workers N` | `256` | Concurrent TCP checks in range discovery. |
| `--port-rate N` | `500` | Maximum TCP connections per second; `0` disables pacing. |
| `--port-timeout-ms N` | `1000` | Retry timeout after the initial 300 ms attempt. |
| `--scheme MODE` | `auto` | Detect TLS on open ports, or force `http` or `https` for `--target`. |
| `--path PATH` | Broad profile | Add a candidate path; repeatable. Custom paths replace the profile. |
| `--paths-file FILE` | — | Read paths; combines with `--path` and replaces the profile. |
| `--path-profile NAME` | `broad` | `standard` (9), `broad` (17), or `extensive` (28). |
| `--format FORMAT` | `text` | `text`, `json`, or `jsonl`. |
| `--color MODE` | `auto` | `auto`, `always`, or `never`; auto respects `NO_COLOR`. |
| `--schemas` | off | Include full tool input schemas in text output. |
| `--http-probe MODE` | `basic` for checked targets; `off` for `--url` or `--no-port-scan` | `off`, `basic` (`HEAD /`, `OPTIONS /`), or `extended` (also bounded `GET /`). Checked targets still use HTTP identification before MCP paths. |
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
| `--user-agent VALUE` | `MCPEnum/0.2.0` | Set the HTTP User-Agent. |

For the current flag list, run `mcpenum --help`; use `mcpenum --version` to identify the build.

## Reading results

MCPEnum keeps scan completion, MCP detection, authentication, and each inventory list separate.

For pentest triage, the text report groups every identified HTTP port and marks the MCP paths confirmed on it. Each confirmed endpoint then shows the transport, self-reported server name/version, anonymous versus credentialed access, advertised tool names and parameters, resources, prompts, and review leads. JSON/JSONL retains the observations and evidence IDs for later validation. These are inventory clues for manual assessment; listing a tool does not establish that it is callable or vulnerable.

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
