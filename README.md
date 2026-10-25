# MCPEnum

[![Go CI](https://github.com/capivara-research/MCPEnum/actions/workflows/ci.yml/badge.svg)](https://github.com/capivara-research/MCPEnum/actions/workflows/ci.yml)
[![MIT license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**MCP reconnaissance in one Go binary.** MCPEnum discovers HTTP-accessible [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) endpoints and inventories their advertised tools, resources, resource templates, and prompts. It records access and protocol evidence and highlights declarations for manual review.

> **Scope:** MCPEnum is a read-only inventory tool. It does not call tools, read resources, run prompts, or test vulnerabilities. It supports Streamable HTTP and legacy HTTP+SSE; it does not launch stdio servers. Build from source; prebuilt binaries are not currently published.

## Quick start

Requires Go 1.22 or newer.

```sh
git clone https://github.com/capivara-research/MCPEnum.git
cd MCPEnum
go build -o mcpenum ./cmd/mcpenum
./mcpenum scan --target 127.0.0.1:8000
```

Replace the example with a host and port in your authorized scope. You do not need to know the endpoint path: the default profile tests 17 candidates on the selected port and reports confirmed MCP endpoints. A `host:port` target tests only that port; a host without a port uses `443,3000,8000,8080`. It does not discover arbitrary paths or scan other ports.

For an endpoint you already know, use its exact URL:

```sh
./mcpenum scan --url https://mcp.example.test/api/mcp
```

The banner and progress go to `stderr`; the report goes to `stdout`. Use `--verbose` for request-level progress or `--format json` for machine-readable output.

## Endpoint discovery

`--url` scans only the supplied URL. `--target` combines selected ports and candidate paths; a `host:port` target uses that port only. The endpoint is confirmed through MCP protocol responses, not from an HTTP 200 alone.

| Profile | Paths per selected port | Use |
|---|---:|---|
| `standard` | 9 | Faster check of common MCP and SSE paths. |
| `broad` (default) | 17 | Nmap’s 15 MCP candidates, `/api/v1/mcp`, and `/mcp/transport`. |
| `extensive` | 28 | Additional nested, versioned, and SSE paths. |

The candidate set is a curated list, not a protocol standard or an exhaustive search. It includes the paths in the pinned [`nmap-ai-recon` MCP library](https://github.com/insidetrust/nmap-ai-recon/blob/86e94bda9dbb1defc4aed61adb4b67b80e422c43/nselib/mcp.lua), `/api/v1/mcp` observed in FastMCP, and `/mcp/transport` from SecLists’ pinned [`mcp-server.txt`](https://github.com/danielmiessler/SecLists/blob/ab068333d7d44a9376e2037b0ed7d2e8ca5c6610/Discovery/Web-Content/mcp-server.txt). SecLists is not a runtime dependency. Candidate requests can create server logs; use only authorized targets and tune `--rate`, `--workers`, or time limits for larger scans.

Choose a profile or supply known paths:

```sh
./mcpenum scan --target 10.0.0.5:8000 --path-profile standard
./mcpenum scan --target 10.0.0.5 --ports 8000,8080 --path-profile extensive
./mcpenum scan --target 10.0.0.5:8000 --path /tenant/team/mcp
```

For several custom paths, use `--paths-file`. Each nonblank line is one path; blank lines and lines beginning with `#` are ignored. Custom paths replace the built-in profile, and repeated `--path` values combine with the file. The limit is 128 paths, each up to 256 bytes.

```text
# paths.txt
/tenant/team/mcp
/api/custom-mcp
```

```sh
./mcpenum scan --target 10.0.0.5:8000 --paths-file paths.txt
```

MCPEnum does not discover arbitrary private prefixes. If a candidate is missed, provide the known path or use the `extensive` profile; a negative result applies only to the paths and ports tested.

## Example output

This real AI-RTA SecureCorp lab scan was captured on 25 October 2026, before `/mcp/transport` was added. It used only host and port, tested 16 candidates, and confirmed two endpoints. The current default tests 17 candidates.

```sh
./mcpenum scan --target 172.16.12.2:8000 --rate 10 --progress always
```

Selected lines from the report:

```text
DISCOVERY SUMMARY  candidates: 16 | MCP endpoints: 2 | aliases: 0 | inconclusive: 2 | other: 12

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

The scan listed advertised tools but did not call them. HTTP 200 responses without MCP confirmation remain inconclusive.

## Common commands

```sh
# Known endpoint
./mcpenum scan --url https://mcp.example.test/mcp

# Host and port, endpoint unknown
./mcpenum scan --target mcp.example.test:8000

# Scoped targets from a file; one URL, host, or host:port per line
./mcpenum scan --targets-file scope.txt --workers 8 --rate 20

# Compare anonymous and Bearer-token inventories
./mcpenum scan --url https://mcp.example.test/mcp --token-env MCPENUM_TOKEN

# JSON output and request-level trace
./mcpenum scan --target mcp.example.test:8000 --format json --verbose
```

Set `MCPENUM_TOKEN` before the token example. The scanner checks anonymous access first, then repeats discovery and inventory with the Bearer token. Tokens and session ID values are not printed. `--token-file PATH` is also available.

`--targets-file` accepts blank lines and `#` comments. CIDR expansion requires `--allow-cidr` and is bounded by `--max-hosts`. MCPEnum does not perform Nmap-style TCP port discovery; choose the ports to test.

## Options

| Option | Default | Purpose |
|---|---:|---|
| `--url URL` | — | Exact HTTP(S) MCP URL; repeatable. |
| `--target HOST[:PORT]` | — | Expand a host across selected ports and paths; repeatable. |
| `--targets-file FILE` | — | Read URLs, hosts, or host:port values, one per line. |
| `--ports LIST` | `443,3000,8000,8080` | Ports or short ranges used with `--target`. |
| `--path PATH` | Broad profile | Add a candidate path; repeatable. Custom paths replace the profile. |
| `--paths-file FILE` | — | Read paths; combines with `--path` and replaces the profile. |
| `--path-profile NAME` | `broad` | `standard` (9), `broad` (17), or `extensive` (28). |
| `--format FORMAT` | `text` | `text`, `json`, or `jsonl`. |
| `--color MODE` | `auto` | `auto`, `always`, or `never`; auto respects `NO_COLOR`. |
| `--schemas` | off | Include full tool input schemas in text output. |
| `--profile NAME` | `inventory` | Scan profile; only `inventory` is implemented. |
| `--http-probe MODE` | `basic` | `off`, `basic` (`HEAD /`, `OPTIONS /`), or `extended` (also bounded `GET /`). |
| `--progress MODE` | `auto` | One progress line on `stderr`: `auto`, `always`, or `never`. |
| `--verbose` | off | Log candidate starts and protocol requests on `stderr`. |
| `--quiet` | off | Suppress banner and progress; cannot be combined with `--verbose`. |
| `--token-env NAME` | — | Read a Bearer token from an environment variable. |
| `--token-file FILE` | — | Read a Bearer token from a file. |
| `--timeout-ms N` | `5000` | Timeout per request. |
| `--budget-ms N` | `30000` | Time budget per endpoint. |
| `--workers N` | `16` | Maximum concurrent endpoint workers. |
| `--rate N` | `0` | Maximum HTTP requests per second; `0` disables pacing. |
| `--max-pages N` | `32` | Maximum pages per collection. |
| `--max-items N` | `5000` | Maximum items per collection. |
| `--max-body N` | `2097152` | Maximum response body size in bytes. |
| `--allow-cidr` | off | Enable CIDR expansion. |
| `--max-hosts N` | `16` | Maximum hosts expanded from a CIDR. |
| `--insecure` | off | Disable TLS certificate verification for controlled tests. |
| `--user-agent VALUE` | `MCPEnum/0.1.0` | Set the HTTP User-Agent. |

For the current flag list, run `./mcpenum scan --help`.

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

JSON results include target data, confirmed services, list inventories, observations, evidence IDs, and request metrics. JSONL emits one result per target. For field definitions and the evidence model, see [How MCPEnum performs a scan](docs/TECHNICAL.md).

## Safety and limits

- The scanner sends protocol discovery and list requests, plus bounded HTTP probes by default. A legacy handshake can create a server-side session.
- It does not send `tools/call`, `resources/read`, or `prompts/get`.
- TLS verification is enabled by default. Redirects remain on the original target origin.
- Use only systems in your authorized scope. Candidate requests may be recorded by the target.

MCPEnum inventories HTTP-accessible servers; it does not replace network discovery, test vulnerabilities, execute payloads, or verify CVEs.

## Validation and development

The automated tests cover modern and legacy protocol behavior, pagination, authentication separation, malformed responses, output escaping, and endpoint discovery. Local interoperability checks cover Go, TypeScript, Python, and Rust MCP servers, including legacy SSE and custom paths. See [validation details](docs/VALIDATION.md) and the [technical scan flow](docs/TECHNICAL.md).

Run the project checks with:

```sh
go test ./...
go test -race ./...
go vet ./...
go build -o mcpenum ./cmd/mcpenum
```

The project has no third-party Go runtime dependencies. See [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), and [LICENSE](LICENSE). Developed by [Fernando Viana (capivara-research)](https://github.com/capivara-research).
