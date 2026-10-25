# MCPEnum

[![Go CI](https://github.com/capivara-research/MCPEnum/actions/workflows/ci.yml/badge.svg)](https://github.com/capivara-research/MCPEnum/actions/workflows/ci.yml)
[![MIT license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**MCP reconnaissance in one Go binary.** MCPEnum discovers HTTP-accessible [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) endpoints and prints a structured inventory in the terminal. It identifies the protocol version, compares anonymous and Bearer-token access, follows list pagination, and highlights declarations worth manual review. It has no Nmap or Python runtime dependency.

**Developed by [Fernando Viana (capivara-research)](https://github.com/capivara-research).**

| Discover | Enumerate | Interpret |
|---|---|---|
| Confirm MCP and its protocol era. | List tools, resources, resource templates, and prompts. | Separate observed facts, incomplete results, and inferred review leads. |

> **Scope:** HTTP and legacy HTTP+SSE inventory. The scanner does not call tools, read resources, run prompts, or test vulnerabilities. Current release: `inventory` profile; build from source because prebuilt binaries are not published yet.

## Quick start

Requires **Go 1.22+**.

```sh
git clone https://github.com/capivara-research/MCPEnum.git
cd MCPEnum
go build -o mcpenum ./cmd/mcpenum
./mcpenum scan --target 127.0.0.1 --ports 8000
```

Replace `127.0.0.1` and `8000` with an authorized host and port. This command tries seven common MCP paths on that port, including `/mcp`, `/`, and `/sse`. It does not discover arbitrary paths. The address above is an example, not a required local service. A successful build creates the `mcpenum` scanner binary; it does not start an MCP server.

An alternative installation, verified against this repository, is:

```sh
go install github.com/capivara-research/MCPEnum/cmd/mcpenum@latest
mcpenum scan --target 127.0.0.1 --ports 8000
```

The second command assumes your Go binary directory is on `PATH`. Building from a clone works without that PATH setup.

A successful scan begins with a compact summary; [the full example](#example-terminal-output) shows the section layout and listed items:

```text
TARGET  http://127.0.0.1:13004/mcp
Result: complete | 5 requests | 14 ms
Summary: MCP confirmed | anonymously listed tools: 1 (complete) | review leads: 0

IDENTIFICATION → ACCESS → INVENTORY ANONYMOUS → OBSERVATIONS
```

The preview is illustrative; counts and timing depend on the server and network.

The default output is a human-readable report on stdout. Its section headings are yellow when stdout is a color-capable terminal. Use `--color always` to force color or `--color never` for plain text.

MCPEnum's own headings and messages are in English. Server-supplied names and descriptions are shown in their original language so the evidence is not altered.

## Contents

- [Choosing an IP and endpoint](#choosing-an-ip-and-endpoint)
- [What MCPEnum looks for](#what-mcpenum-looks-for)
- [Example terminal output](#example-terminal-output)
- [Common commands](#common-commands)
- [Options](#options)
- [Reading the results correctly](#reading-the-results-correctly)
- [JSON output and automation](#json-output-and-automation)
- [Protocol, access, and safety](#protocol-access-and-safety)
- [Validation and compatibility](#validation-and-compatibility)
- [Troubleshooting and FAQ](#troubleshooting-and-faq)
- [Development, support, and license](#development-support-and-license)

## Choosing an IP and endpoint

Use `--url` when you know the exact endpoint. It accepts a reachable `http://` or `https://` URL for **any authorized target IP or DNS name**:

```sh
./mcpenum scan --url http://10.0.0.5:8000/mcp
./mcpenum scan --url https://mcp.example.test/api/mcp
```

If you know the host but not the endpoint, use `--target` to try selected ports and paths:

```sh
./mcpenum scan --target 10.0.0.5 --ports 8000,8080 --path /mcp --path /api/mcp
```

| What you know | Use | What MCPEnum tries |
|---|---|---|
| Exact URL, including scheme and path | `--url` | That URL only. If the path is omitted, it uses `/mcp` only. |
| Host and candidate ports/paths | `--target`, `--ports`, `--path` | The selected combinations. |
| Several scoped hosts or URLs | `--targets-file` | Each line as a host or exact URL. |
| A small scoped subnet | `--target CIDR --allow-cidr` | Hosts up to `--max-hosts`, then selected ports/paths. |

`--target` tests each selected port/path combination; `--url` does **not** search alternate paths. Neither mode discovers arbitrary paths or ports. A normal web API, incorrect path, unreachable port, unsupported stdio-only server, or access control that prevents confirmation cannot produce a valid MCP inventory. See [result states](#reading-the-results-correctly) before interpreting an empty report.

If a candidate is not confirmed as MCP, the text report shows the discovery requests, HTTP status, error category, and any `Server` and `Content-Type` headers. For example, a missing path can show `server/discover: HTTP 404 ... | server: uvicorn`. These headers are self-reported clues about the HTTP service, not proof of its product or version. A failed candidate says nothing about other paths on the host.

The standard path set is `/mcp`, `/`, `/sse`, `/api/mcp`, `/mcp/v1`, `/v1/mcp`, and `/messages`. For a wider search, use `--path-profile broad`: it tries 15 MCP-related paths. More paths produce more requests and more result rows. A repeated `--path` option replaces either built-in set with only the paths you name.

```sh
./mcpenum scan --target 10.0.0.5 --ports 8000 --path-profile broad
./mcpenum scan --target 10.0.0.5 --ports 8000 --path /custom/mcp --path /rpc
```

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

Review leads currently cover state-changing names, internal-only markers, process execution terms, file and network access, environment variables, credential terms, database terms, descriptions of unsafe input, invisible/control characters, assistant-directed instructions, and terminal output control options. The tool does not assign a CVE or claim exploitability from any of these terms.

For the modern MCP revision (`2026-07-28`), MCPEnum uses `server/discover` and request metadata. For handshake-era servers (`2025-11-25` and earlier), it falls back to `initialize` and `notifications/initialized`. The same endpoint may support both eras. A nonstandard or missing version in `initialize` requires a valid `tools/list` response before MCPEnum marks the service confirmed. See the [MCP versioning specification](https://modelcontextprotocol.io/specification/2026-07-28/basic/versioning) for the distinction between eras.

The default scan sends only discovery, handshake, metadata, and `*/list` requests. It never sends `tools/call`, `resources/read`, or `prompts/get`. A legacy `initialize` can create a server-side session; MCPEnum reports whether a session ID was observed without printing its value.

| Scan phase | Requests MCPEnum may send | Purpose |
|---|---|---|
| Modern discovery | `server/discover` | Confirm a modern MCP server and read advertised capabilities. |
| Legacy fallback | `initialize`, then `notifications/initialized` | Negotiate a handshake-era revision when modern discovery does not confirm one. |
| Inventory | `tools/list`, `resources/list`, `resources/templates/list`, `prompts/list` | Collect each list and follow pagination within configured limits. |
| Authentication metadata | Same-origin OAuth protected-resource metadata request when advertised | Describe the challenge without contacting an authorization server. |

The number of requests varies with protocol era, pagination, authentication, and failures. `requests` in the report is the observed count for that endpoint.

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
  Finding (confirmed): 1 resource listed anonymously
```

The section dividers separate identification, access, inventory, and observations. When a collection fails, its row shows `failed` and an error code instead of silently showing zero items. `--schemas` adds full tool input schemas to the text view.

When a server advertises tools whose declarations suggest sensitive capabilities, they move into **TOOLS WITH REVIEW LEADS**. For example, an authorized local training server produced these lines (other tools omitted):

```text
  TOOLS WITH REVIEW LEADS (6)
    1. read_file
       Inferred leads: file access
       Description: Reads file contents from the filesystem. Supports relative and absolute paths.
       Required: path (string)
    2. execute_system_command
       Inferred leads: process execution
       Required: command (string)
```

The labels describe advertised metadata. MCPEnum did not invoke either tool, so this output alone does not prove that either operation is executable or unauthenticated.

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

With `--target`, MCPEnum expands the selected ports and paths. Default ports are `443,3000,8000,8080`; the seven standard paths are listed [above](#choosing-an-ip-and-endpoint). Port 443 uses HTTPS; other default ports use HTTP. Specify `--url` when the exact scheme matters. MCPEnum probes only the selected ports; it does not perform Nmap-style TCP port discovery.

### Scan multiple authorized targets

```sh
./mcpenum scan --targets-file scope.txt --workers 8 --rate 20
```

`scope.txt` accepts one URL, host, or `host:port` per line. Blank lines and lines starting with `#` are ignored. CIDR expansion is opt-in and bounded:

```text
# scope.txt — replace these examples with systems in your scope
http://10.0.0.5:8000/mcp
10.0.0.6:8080
mcp.example.test
```

For a `host:port` entry, the selected paths still apply. An explicit URL uses only its own path. The scanner does not parse Nmap output or discover ports outside the ones you selected.

```sh
./mcpenum scan --target 192.0.2.0/29 --allow-cidr --max-hosts 8 --ports 8000
```

### Compare anonymous and credentialed inventory

```sh
./mcpenum scan --url https://mcp.example.test/mcp --token-env MCPENUM_TOKEN
```

Set `MCPENUM_TOKEN` in your environment before running the command. MCPEnum scans anonymously first, then repeats discovery and inventory with `Authorization: Bearer …`. Results are kept in separate `anonymous` and `credentialed` inventories. `--token-file PATH` is available when a token is stored in a file. Tokens and session IDs are not printed in the report.

```sh
./mcpenum scan --url https://mcp.example.test/mcp --token-file ./mcp-token.txt
```

The token file should contain the token itself, without a `Bearer ` prefix. Protect it with appropriate filesystem permissions. MCPEnum does not accept a literal `--token` argument, so the scanner command does not need to contain the secret. If you set a token by typing a literal `export` command, your shell may still record that command in its history.

### Use machine-readable output

```sh
./mcpenum scan --url http://127.0.0.1:8000/mcp --format json
./mcpenum scan --targets-file scope.txt --format jsonl > results.jsonl
```

`json` prints one object for one target or an array for multiple targets. `jsonl` prints one object per target. Each result includes `schema_version`, `target`, `scan_status`, `services`, `observations`, and `metrics`. Collection objects include `status`, `pages`, `count`, `items`, and evidence IDs. Text and JSON describe the same scan; JSON retains more detail for automation.

### Tune output and scan limits

```sh
./mcpenum scan --url http://127.0.0.1:8000/mcp --schemas --color always
./mcpenum scan --target 10.0.0.5 --ports 8000 --timeout-ms 3000 --budget-ms 15000 --max-pages 10 --max-items 1000 --rate 5
```

`--schemas` reveals complete input schemas in text output. `--color always` forces colored headings, including when output is piped. In automatic color mode, `NO_COLOR`, `TERM=dumb`, or redirected stdout disables color. The limits above keep a slow or paginated endpoint bounded; hitting a limit is reported as partial or timed out, not silently treated as absence of MCP.

## Options

| Option | Default | Purpose |
|---|---:|---|
| `--url URL` | — | Exact MCP URL; repeatable. |
| `--target HOST[:PORT]` | — | Expand host with selected ports and paths; repeatable. |
| `--targets-file FILE` | — | Read URLs or hosts, one per line. |
| `--ports LIST` | `443,3000,8000,8080` | Comma-separated ports or short ranges for `--target`. |
| `--path PATH` | Seven standard paths | Candidate path for `--target`; repeatable and replaces the path profile. |
| `--path-profile` | `standard` | `standard` (7 paths) or `broad` (15 paths) for `--target`. |
| `--format` | `text` | `text`, `json`, or `jsonl`. |
| `--color` | `auto` | `auto`, `always`, or `never` for text output. `NO_COLOR` is respected in auto mode. |
| `--schemas` | off | Include full tool input schemas in text output. |
| `--profile` | `inventory` | Select the scan profile; only `inventory` is implemented. |
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

The CLI exits with status `2` for invalid arguments or other command errors. A completed command can still report `scan_status: failed`, an inconclusive detection, or a partial list: inspect the result fields instead of using exit status alone as a test for “MCP found.”

## Reading the results correctly

MCPEnum keeps **scan status**, **MCP detection**, **authentication**, and **each list's status** separate. Read them together:

| Field | Examples | Meaning |
|---|---|---|
| `scan_status` | `completed`, `partial`, `failed` | Whether the scan itself completed. `completed` does not mean MCP was found. |
| `detection.status` | `confirmed`, `inconclusive` | Whether the response was sufficient to confirm MCP. A generic HTTP Bearer challenge alone is not confirmation. |
| `authentication.anonymous` | `accepted`, `required`, `unknown`, `error` | What happened while probing without a token. A challenge can be observed before MCP is confirmed. |
| `authentication.credentialed` | `accepted`, `rejected`, `not_tested` | What happened with the configured Bearer token, if any. |
| Collection `status` | `complete`, `empty`, `partial`, `unsupported`, `denied`, `timeout`, `error` | The result of one `*/list` method. Other lists may have different outcomes. |

**Complete** means at least one valid item was listed and pagination ended. **Empty** means the method succeeded with a valid empty list. **Partial** means a limit, repeated cursor, or interrupted enumeration prevented completion. **Unsupported** usually corresponds to JSON-RPC `-32601` (method not found). **Denied** means the list request was refused. **Error** is displayed as `failed` in text output; it is not an empty list. A failed list can make the overall scan `partial` while MCP detection stays `confirmed`.

`confirmed` findings report what the scanner directly observed, such as an anonymously listed item. `inferred` review leads come from names, descriptions, or schemas. Server names and versions are **self-reported**. None of those facts proves that a tool can be executed, that its description is accurate, or that a vulnerability exists.

## JSON output and automation

The JSON output uses `schema_version: "2.0"` and `scanner: "mcpenum"`. Its principal objects are:

| JSON path | Content |
|---|---|
| `target` | Input URL, host, port, and scheme. |
| `services[].detection` | Confirmation state, confidence, reason, and evidence IDs. |
| `services[].authentication` | Anonymous and credentialed access states. |
| `services[].mcp` | Transport, era, negotiated version, self-reported identity, capabilities, and inventories. |
| `services[].mcp.inventories.anonymous` | Four list results from the anonymous context. |
| `services[].mcp.inventories.credentialed` | Four list results when a Bearer token was provided. |
| `services[].findings` | Confirmed exposure observations and inferred review leads. |
| `observations` | Method, phase, path, HTTP/JSON-RPC status, bounded `Server` and `Content-Type` headers, timing, and size for each request. |
| `metrics` | Request count, elapsed time, connection count, and bytes received. |

Each finding and collection refers to relevant observations through `evidence_ids`. This lets an integration trace a conclusion back to the requests that produced it. The scanner does not include Bearer tokens or session ID values in output.

If you have `jq` installed, you can extract a small summary without changing the scan:

```sh
./mcpenum scan --url http://127.0.0.1:8000/mcp --format json \
  | jq '.services[] | {endpoint, protocol_version: .mcp.protocol_version, anonymous_tools: .mcp.inventories.anonymous.tools.count}'
```

`jq` is optional and is used only for the shell post-processing above; MCPEnum itself does not depend on it. For a server with one listed tool, the selected fields look like:

```json
{
  "endpoint": "/mcp",
  "protocol_version": "2026-07-28",
  "anonymous_tools": 1
}
```

When `services` is empty, the `jq` filter returns no rows; inspect `scan_status`, `observations`, and `warnings` to distinguish a negative result from a transport failure. For scripts, do not treat process exit code `0` as proof that MCP was confirmed.

## Protocol, access, and safety

- **Reachability:** MCPEnum uses the network route and proxy configuration available to the Go process. It does not start a VPN, perform a broad TCP port scan, or discover unknown paths beyond those selected with `--target` and `--path`.
- **Transports:** Streamable HTTP is supported for modern and handshake-era MCP. Legacy HTTP+SSE is supported through `/sse`. Local stdio servers are not launched by this release.
- **Authentication:** The scanner understands anonymous access and an optional HTTP Bearer token. It does not log in interactively or authenticate with HTTP Basic, cookies, OAuth authorization-code flows, or client certificates.
- **Request effects:** It sends discovery, handshake, OAuth metadata, and list requests; it does not send `tools/call`, `resources/read`, or `prompts/get`. A legacy handshake may create a server-side session.
- **Limits:** Request timeout, endpoint budget, response size, pagination, CIDR expansion, worker count, and request rate are configurable. Redirects remain on the original target origin. TLS verification is enabled unless `--insecure` is explicitly chosen.
- **Interpretation:** A listed tool may be protected at call time. A review lead is a prompt for human investigation, not an exploit result or CVE confirmation.

Use MCPEnum only on systems within your authorized scope. It is an inventory tool, not an exploit framework: it does not run payloads, verify prompt injection, prove SSRF or SQL injection, or assess CVEs.

## Validation and compatibility

The tests cover modern discovery, older version negotiation, pagination, authentication-state separation, malformed responses, output escaping, and nonstandard-server behavior. In local integration checks, MCPEnum enumerated:

| Server style | Negotiated version | Observed result |
|---|---|---|
| Training server using an early MCP revision | `2024-11-05` | 12 tools, 3 resources, 2 prompts; a resource-template error remained visible. |
| FastMCP v1 server | `2025-11-25` | 14 tools; the three other lists were empty. |
| Official Python SDK v2 server | `2026-07-28` | 1 tool and 1 resource through `server/discover`. |
| Custom CTF bridge, original | Nonstandard `0.1.0` | Inconclusive because `tools/list` failed. |
| Same bridge with a list-serialization compatibility fix | Nonstandard `0.1.0` | 19 tools confirmed; other list failures remained visible. |

These are local fixtures, not claims about every MCP implementation. The CI job runs tests, `go vet`, and a build on Ubuntu. The tool does not need Nmap installed. [How MCPEnum performs a scan](docs/TECHNICAL.md) describes the request flow in more detail.

## Troubleshooting and FAQ

| Question or symptom | What to check |
|---|---|
| **Can I use another IP or endpoint?** | Yes. Give the full reachable HTTP(S) endpoint with `--url`, or use `--target` with selected ports and paths. `127.0.0.1` is only an example. |
| **The command says “MCP not confirmed.”** | Read `PROBE OBSERVATIONS` for HTTP status or error category. Check the scheme, port, and path. An explicit `--url` does not try other paths; the service may be stdio-only or may not be MCP. JSON retains the full observations. |
| **I received 401/403.** | A generic HTTP challenge does not prove MCP. If you have a scoped Bearer token, use `--token-env` or `--token-file` and compare both inventories. |
| **The port is closed or DNS fails.** | Check reachability, routing, VPN state, firewall, scheme, and port. JSON warnings distinguish connection, DNS, and TLS errors when possible. |
| **The TLS certificate is untrusted.** | Use a valid certificate for normal operation. `--insecure` is available for controlled test environments. |
| **A list says `unsupported` or `failed`.** | `unsupported` normally means method-not-found (`-32601`); `failed` is an error such as `-32603`. Neither means an empty collection. |
| **The scan is slow or partial.** | Reduce ports/paths and review `--timeout-ms`, `--budget-ms`, `--max-pages`, `--max-items`, `--workers`, and `--rate`. A lower budget can intentionally reduce completeness. |
| **A tool is listed but cannot be called.** | Listing and execution can have different authorization rules. MCPEnum never calls tools, so call-time access remains untested. |
| **Where are colors?** | Color is automatic only on a compatible terminal. Use `--color always` to force it or `--color never` to suppress it. |
| **Does it replace Nmap?** | MCPEnum has no Nmap runtime dependency and focuses on MCP endpoints. Use a separate network-discovery workflow when you do not know which ports are in scope. |

For help with a reproducible bug or documentation gap, open a [GitHub issue](https://github.com/capivara-research/MCPEnum/issues) without posting live credentials. For a vulnerability in MCPEnum itself, follow [SECURITY.md](SECURITY.md).

## Development, support, and license

```sh
go test ./...
go test -race ./...
go vet ./...
go build -o mcpenum ./cmd/mcpenum
```

The project has no third-party Go runtime dependencies. See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution expectations, [SECURITY.md](SECURITY.md) for private security reporting, and [LICENSE](LICENSE) for the MIT license. The maintained code and documentation are in English; server-supplied metadata is preserved as received.

**Author and maintainer:** [Fernando Viana (capivara-research)](https://github.com/capivara-research). Contributions are welcome through pull requests.
