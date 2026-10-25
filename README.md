# MCPEnum

**MCPEnum** is a lightweight, read-only reconnaissance tool for HTTP-accessible [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) servers. It is written in Go, uses only the Go standard library, and does not require Nmap or Python at runtime.

It discovers MCP endpoints, identifies the negotiated protocol generation, inventories tools, resources, resource templates, and prompts, and prints a structured report directly in the terminal. Tool descriptions and input schemas are analyzed for **review leads** such as file access, network access, environment variables, state changes, and suspicious instructions. A lead is an inference from metadata, never proof that a tool can be called or exploited.

> Current scope: HTTP and legacy HTTP+SSE MCP inventory. MCPEnum does not execute `tools/call`, read resources, run prompts, or test vulnerabilities.

## Quick start

Requires **Go 1.22+**.

```sh
git clone https://github.com/capivara-research/MCPEnum.git
cd MCPEnum
go build -o mcpenum ./cmd/mcpenum
./mcpenum scan --url http://127.0.0.1:8000/mcp
```

The default output is a human-readable report on stdout. Its section headings are yellow when stdout is a color-capable terminal. Use `--color always` to force color or `--color never` for plain text.

## What MCPEnum looks for

| Area | Data collected | How it is interpreted |
|---|---|---|
| Endpoint | HTTP response, MCP JSON-RPC envelope, transport | A generic HTTP response or Bearer challenge alone does not confirm MCP. |
| Protocol | `server/discover` for modern MCP, with `initialize` fallback for older servers | The reported version is the server's response, not merely the version offered by MCPEnum. |
| Identity | Server name, version, capabilities, session behavior | Server identity is self-reported. |
| Access | Anonymous listing; credentialed listing when a Bearer token is provided | Listing access does **not** prove that any listed tool can be executed. |
| Inventory | `tools/list`, `resources/list`, `resources/templates/list`, `prompts/list` | Pagination is followed within configured limits; empty, unsupported, denied, partial, and failed lists stay distinct. |
| Review leads | Tool names, descriptions, and nested input schemas | Leads are marked *inferred* and include their source path in JSON output. |
| Evidence and cost | Per-request observations, request count, duration, bytes received | JSON output retains evidence IDs and collection status. |

For the current MCP revision (`2026-07-28`), MCPEnum uses `server/discover` and request metadata. For handshake-era servers (`2025-11-25` and earlier), it falls back to `initialize` and `notifications/initialized`. The same endpoint may support both eras. A nonstandard or missing version in `initialize` requires a valid `tools/list` response before MCPEnum marks the service confirmed.

The default scan sends only discovery, handshake, metadata, and `*/list` requests. It never sends `tools/call`, `resources/read`, or `prompts/get`. A legacy `initialize` can create a server-side session; MCPEnum reports whether a session ID was observed without printing its value.

For the exact request sequence, collection states, and evidence model, see [How MCPEnum performs a scan](docs/TECHNICAL.md).

## Example terminal output

This sample follows a local test with the official MCP Python SDK v2. The server name has been simplified for documentation; durations and request counts vary by server and network.

```text
TARGET  http://127.0.0.1:13004/mcp
Result: complete | 5 requests | 14 ms
Summary: MCP confirmed | anonymously listed tools: 1 (complete) | review leads: 0

────────────────────────────────────────────────────────────────────────
IDENTIFICATION
  MCP: confirmed | confidence: high
  Endpoint: /mcp
  Server: sdk-v2-fixture 1.0.0 (self-reported)
  Transport: Streamable HTTP | era: modern
  MCP version: 2026-07-28
  Session: stateless
  Advertised capabilities: prompts, resources, tools

────────────────────────────────────────────────────────────────────────
ACCESS
  Anonymous listing: accepted
  Credentialed listing: not tested
  Tool execution: not tested
  Tools listed anonymously: 1

────────────────────────────────────────────────────────────────────────
INVENTORY ANONYMOUS
  Tools:               1 item, complete, 1 page
  Resources:           1 item, complete, 1 page
  Resource templates:  0 items, empty, 1 page
  Prompts:             0 items, empty, 1 page

  OTHER LISTED TOOLS (1)
    1. search_notes
       Description: Search public test notes by query.
       Required: query (string)

  LISTED RESOURCES (1)
    1. fixture://info

────────────────────────────────────────────────────────────────────────
OBSERVATIONS
  Review leads come from advertised definitions; no tools/call was sent.
  Finding (confirmed): 1 resources listed anonymously
```

The section dividers separate identification, access, inventory, and observations. When a collection fails, its row shows `failed` and an error code instead of silently showing zero items. `--schemas` adds full tool input schemas to the text view.

## Common commands

### Scan an exact MCP URL

```sh
./mcpenum scan --url https://mcp.example.test/mcp
```

An explicit `--url` probes only that URL. If the path is omitted, `/mcp` is used.

### Search selected ports and paths

```sh
./mcpenum scan --target mcp.example.test --ports 443,8000 --path /mcp --path /api/mcp
```

With `--target`, MCPEnum expands the selected ports and paths. Default ports are `443,3000,8000,8080`; default paths are `/mcp`, `/api/mcp`, and `/sse`. Port 443 uses HTTPS; other default ports use HTTP. Specify `--url` when the exact scheme matters.

### Scan multiple authorized targets

```sh
./mcpenum scan --targets-file scope.txt --workers 8 --rate 20
```

`scope.txt` accepts one URL, host, or `host:port` per line. Blank lines and lines starting with `#` are ignored. CIDR expansion is opt-in and bounded:

```sh
./mcpenum scan --target 192.0.2.0/29 --allow-cidr --max-hosts 8 --ports 8000
```

### Compare anonymous and credentialed inventory

```sh
export MCPENUM_TOKEN='replace-with-your-token'
./mcpenum scan --url https://mcp.example.test/mcp --token-env MCPENUM_TOKEN
```

MCPEnum scans anonymously first, then repeats discovery and inventory with `Authorization: Bearer …`. Results are kept in separate `anonymous` and `credentialed` inventories. `--token-file PATH` is available when a token is stored in a file. Tokens and session IDs are not printed in the report.

### Use machine-readable output

```sh
./mcpenum scan --url http://127.0.0.1:8000/mcp --format json
./mcpenum scan --targets-file scope.txt --format jsonl > results.jsonl
```

`json` prints one object for one target or an array for multiple targets. `jsonl` prints one object per target. Each result includes `schema_version`, `target`, `scan_status`, `services`, `observations`, and `metrics`. Collection objects include `status`, `pages`, `count`, `items`, and evidence IDs. Text and JSON describe the same scan; JSON retains more detail for automation.

## Options

| Option | Default | Purpose |
|---|---:|---|
| `--url URL` | — | Exact MCP URL; repeatable. |
| `--target HOST[:PORT]` | — | Expand host with selected ports and paths; repeatable. |
| `--targets-file FILE` | — | Read URLs or hosts, one per line. |
| `--ports LIST` | `443,3000,8000,8080` | Comma-separated ports or short ranges for `--target`. |
| `--path PATH` | `/mcp`, `/api/mcp`, `/sse` | Candidate path for `--target`; repeatable. |
| `--format` | `text` | `text`, `json`, or `jsonl`. |
| `--color` | `auto` | `auto`, `always`, or `never` for text output. `NO_COLOR` is respected in auto mode. |
| `--schemas` | off | Include full tool input schemas in text output. |
| `--token-env NAME` | — | Read a Bearer token from an environment variable. |
| `--token-file FILE` | — | Read a Bearer token from a file. |
| `--timeout-ms N` | `5000` | Timeout for each request. |
| `--budget-ms N` | `30000` | Total time budget per endpoint. |
| `--workers N` | `16` | Maximum concurrent endpoint workers. |
| `--rate N` | `0` | Global maximum HTTP requests per second; `0` disables pacing. |
| `--max-pages N` | `32` | Maximum pages per collection. |
| `--max-items N` | `5000` | Maximum items per collection. |
| `--max-body N` | `2097152` | Maximum response bytes. |
| `--allow-cidr` / `--max-hosts N` | off / `16` | Explicitly enable and limit CIDR expansion. |
| `--insecure` | off | Disable TLS certificate verification for a test environment. |
| `--user-agent VALUE` | `MCPEnum/0.1.0` | Set the HTTP User-Agent. |

Run `./mcpenum scan --help` for the live flag list. A target is required; a bare `mcpenum` command prints usage.

## Reading the results correctly

- **Confirmed** means an MCP discovery response or valid handshake was observed. For a nonstandard handshake, MCPEnum additionally requires a valid MCP list.
- **Inconclusive** means there was an MCP-shaped lead but not enough evidence to confirm the service.
- **Complete / empty** means the list method succeeded and pagination ended. **Partial** means an item, page, cursor, or time limit interrupted it.
- **Unsupported** usually means JSON-RPC `-32601` (method not found). **Denied** indicates access was refused. **Failed** is an error, not an empty list.
- **Review leads** are metadata heuristics. They do not assert that a listed tool is callable, that authentication is bypassed, or that a vulnerability exists.

## Boundaries and current limitations

MCPEnum is an inventory tool, not an exploit framework. It does not perform `tools/call`, read returned secrets, test prompt injection, verify SSRF or SQL injection, or match CVEs. It does not currently launch local stdio servers. Server names and versions are self-reported. Tool metadata can be inaccurate or intentionally deceptive. The tool reports what it observed and keeps errors and incomplete scans visible.

MCPEnum limits redirects to the target origin and enforces request, response, pagination, and host-expansion bounds. Use it only on systems within your authorized scope.

## Development

```sh
go test ./...
go vet ./...
go build -o mcpenum ./cmd/mcpenum
```

The test suite includes modern and older MCP negotiation, pagination, authentication-state separation, malformed responses, output safety, and nonstandard-server behavior. See [CONTRIBUTING.md](CONTRIBUTING.md) for changes and [SECURITY.md](SECURITY.md) for reporting security issues.

## License

MIT. See [LICENSE](LICENSE).
