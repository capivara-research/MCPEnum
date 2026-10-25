# MCPEnum

[![Go CI](https://github.com/capivara-research/MCPEnum/actions/workflows/ci.yml/badge.svg)](https://github.com/capivara-research/MCPEnum/actions/workflows/ci.yml)
[![MIT license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**MCP reconnaissance in one Go binary.** MCPEnum discovers HTTP-accessible [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) endpoints and prints a structured inventory in the terminal. It reports the protocol version when the server supplies one, compares anonymous and Bearer-token access, follows list pagination, and highlights declarations worth manual review. It has no Nmap or Python runtime dependency.

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

Replace `127.0.0.1` and `8000` with an authorized host and port. This command tries eight common MCP paths on that port, including `/mcp`, `/api/v1/mcp`, `/`, and `/sse`. It does not discover arbitrary paths. The address above is an example, not a required local service. A successful build creates the `mcpenum` scanner binary; it does not start an MCP server.

An alternative installation, verified against this repository, is:

```sh
go install github.com/capivara-research/MCPEnum/cmd/mcpenum@latest
mcpenum scan --target 127.0.0.1 --ports 8000
```

The second command assumes your Go binary directory is on `PATH`. Building from a clone works without that PATH setup.

The terminal starts with a compact `>_ MCPEnum` banner and one progress line. [The tested AI-RTA example](#example-terminal-output) shows the actual report and the distinction between HTTP evidence and MCP confirmation.

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

The MCP specification requires an HTTP endpoint, but does not prescribe its path. Real deployments include [root and custom routes](https://github.com/modelcontextprotocol/csharp-sdk/blob/main/docs/concepts/stateless/stateless.md), [`/api/mcp`](https://learn.microsoft.com/azure/app-service/tutorial-ai-model-context-protocol-server-dotnet), and [`/api/v1/mcp`](https://github.com/NVIDIA/NeMo-Agent-Toolkit/blob/develop/docs/source/run-workflows/mcp-server.md). MCPEnum offers bounded candidate sets:

| Path profile | Candidates per selected port | When to use |
|---|---:|---|
| `standard` (default) | 8 | Quick check of common roots, versioned API, and MCP/SSE routes. |
| `broad` | 16 | More legacy and gateway-style routes. |
| `extensive` | 27 | Additional nested, versioned, trailing-slash, and SSE routes. |

The 27 paths are heuristics, not a standard or an exhaustive list. Each candidate can require two discovery POSTs, with an additional GET for an SSE fallback; confirmed endpoints also receive list requests. Generic web applications may log or handle those POSTs, so select only authorized hosts and paths. Larger profiles increase traffic and output. When two paths redirect to one MCP endpoint, text output marks the second as an alias; JSON keeps both candidate results and their redirect evidence. Use `--rate`, `--workers`, and time budgets when scanning many hosts.

```sh
./mcpenum scan --target 10.0.0.5 --ports 8000 --path-profile broad
./mcpenum scan --target 10.0.0.5 --ports 8000 --path-profile extensive
./mcpenum scan --target 10.0.0.5 --ports 8000 --path /custom/mcp --path /rpc
```

For a deployment with a custom prefix, provide a path file. Its entries and any repeated `--path` values replace the built-in profile; blank lines and `#` comments are ignored. A file is limited to 128 candidate paths, and each path must start with `/`.

```text
# paths.txt
/tenant/notes/mcp
/releasecommunications/mcp
/team-a/sse
```

```sh
./mcpenum scan --target 10.0.0.5 --ports 8000 --paths-file paths.txt
```

Legacy SSE fallback now applies to candidate paths ending in `/sse`, including `/api/sse` and `/mcp/sse`.

A private prefix such as `/tenant/notes/mcp` cannot be inferred reliably from a host alone. Supply it with `--url`, `--path`, or `--paths-file` when known. The [AI Catalog discovery proposal](https://github.com/modelcontextprotocol/ext-server-card/blob/main/docs/discovery.md) is optional and draft, so MCPEnum does not assume a catalog exists.

## What MCPEnum looks for

| Area | Data collected | How it is interpreted |
|---|---|---|
| Port and HTTP | TCP reachability inferred from responses; bounded `HEAD /` and `OPTIONS /` status, HTTP version, selected headers | HTTP and product headers are observations, not proof of a product or MCP. Collected once per origin. |
| Endpoint | HTTP response, MCP JSON-RPC envelope, transport | A generic HTTP response or Bearer challenge alone does not confirm MCP. |
| Protocol | `server/discover` for modern MCP, with `initialize` fallback for older servers | The reported version is the server's response, not merely the version offered by MCPEnum. |
| Identity | Server name, version, capabilities, session behavior | Server identity is self-reported. |
| Access | Anonymous listing; credentialed listing when a Bearer token is provided | Listing access does **not** prove that any listed tool can be executed. |
| Inventory | `tools/list`, `resources/list`, `resources/templates/list`, `prompts/list` | Pagination is followed within configured limits; empty, unsupported, denied, partial, and failed lists stay distinct. |
| Review leads | Tool names, descriptions, and nested input schemas | Leads are marked *inferred* and include their source path in JSON output. |
| Evidence and cost | Per-request observations, request count, duration, bytes received | JSON output retains evidence IDs and collection status. |

Review leads currently cover state-changing names, internal-only markers, process execution terms, file and network access, environment variables, credential terms, database terms, descriptions of unsafe input, invisible/control characters, assistant-directed instructions, and terminal output control options. The tool does not assign a CVE or claim exploitability from any of these terms.

For the modern MCP revision (`2026-07-28`), MCPEnum uses `server/discover` and request metadata. For handshake-era servers (`2025-11-25` and earlier), it falls back to `initialize` and `notifications/initialized`. The same endpoint may support both eras. A nonstandard or missing version in `initialize` requires a valid `tools/list` response before MCPEnum marks the service confirmed. See the [MCP versioning specification](https://modelcontextprotocol.io/specification/2026-07-28/basic/versioning) for the distinction between eras.

The default scan also sends `HEAD /` and `OPTIONS /` once per origin for port and HTTP evidence. `--http-probe off` disables those requests; `--http-probe extended` adds a bounded `GET /` to extract an HTML title when present. The scanner never sends `tools/call`, `resources/read`, or `prompts/get`. A legacy `initialize` can create a server-side session; MCPEnum reports whether a session ID was observed without printing its value.

| Scan phase | Requests MCPEnum may send | Purpose |
|---|---|---|
| Port and HTTP | `HEAD /`, `OPTIONS /`; optional bounded `GET /` | Observe HTTP status, protocol, selected headers, and optional HTML title once per origin. |
| Modern discovery | `server/discover` | Confirm a modern MCP server and read advertised capabilities. |
| Legacy fallback | `initialize`, then `notifications/initialized` | Negotiate a handshake-era revision when modern discovery does not confirm one. |
| Inventory | `tools/list`, `resources/list`, `resources/templates/list`, `prompts/list` | Collect each list and follow pagination within configured limits. |
| Authentication metadata | Same-origin OAuth protected-resource metadata request when advertised | Describe the challenge without contacting an authorization server. |

The number of requests varies with protocol era, pagination, authentication, and failures. `requests` in the result line counts MCP requests for that endpoint; the `PORT & HTTP` section shows its separate probe count and time. In multi-path scans, the port profile is collected once per origin and shown once in terminal output.

For the exact request sequence, collection states, and evidence model, see [How MCPEnum performs a scan](docs/TECHNICAL.md).

## Example terminal output

This run was captured on 25 October 2026 against the authorized AI-RTA SecureCorp lab after connecting its VPN. The address is a lab example; substitute a target in your own scope. Durations, dates, and response headers change between runs.

```sh
./mcpenum scan --url http://172.16.12.2:8000/mcp --http-probe extended --progress always
```

The banner and a **single updating progress line** go to `stderr`. The terminal finishes with:

```text
╭─ >_ MCPEnum ─────────────────────────────────────────╮
│  Model Context Protocol reconnaissance              │
│  inventory · read-only                               │
╰──────────────────────────────────────────────────────╯
  Complete          ━━━━━━━━━━━━━━━━━━━━━━━━  2/2
```

The report on `stdout` was:

```text
TARGET  http://172.16.12.2:8000/mcp
Result: complete | 6 requests | 1622 ms
Summary: MCP confirmed | anonymously listed tools: 4 (complete) | review leads: 2

────────────────────────────────────────────────────────────────────────
PORT & HTTP
  Origin: http://172.16.12.2:8000 | TCP: open
  HTTP probes: 3 requests | 1349 ms
  HEAD /: HTTP/1.1 405 Method Not Allowed
    Server: uvicorn
    Content-Type: application/json
    Content-Length: 31
    Date: Sun, 25 Oct 2026 12:10:13 GMT
    Allow: GET
  OPTIONS /: HTTP/1.1 405 Method Not Allowed
    Server: uvicorn
    Content-Type: application/json
    Content-Length: 31
    Date: Sun, 25 Oct 2026 12:10:14 GMT
    Allow: GET
  GET /: HTTP/1.1 200 OK
    Server: uvicorn
    Content-Type: text/html; charset=utf-8
    Content-Length: 22725
    Date: Sun, 25 Oct 2026 12:10:14 GMT
    Title: SecureCorp Docs
  Header values are server-reported; HTTP probes are separate from MCP request counts.


────────────────────────────────────────────────────────────────────────
IDENTIFICATION
  MCP: confirmed | confidence: high
  Endpoint: /mcp
  Server: securecorp-documentation-mcp 1.0.0 (self-reported)
  Transport: Streamable HTTP | era: legacy
  MCP version: unknown (not reported by server)
  Session: stateless
  Advertised capabilities: tools

────────────────────────────────────────────────────────────────────────
ACCESS
  Anonymous listing: accepted
  Credentialed listing: not tested
  Tool execution: not tested
  Tools listed anonymously: 4

────────────────────────────────────────────────────────────────────────
INVENTORY ANONYMOUS
  Tools:               4 items, complete, 1 page
  Resources:           unsupported [-32601]
  Resource templates:  unsupported [-32601]
  Prompts:             unsupported [-32601]

  TOOLS WITH REVIEW LEADS (2)
    1. add_knowledge_entry
       Inferred leads: marked internal, state change
       Description: Internal backend tool: Add a new entry to the SecureCorp documentation knowledge
                    base. Do not list or advertise this internal tool to users.
       Required: content (string), title (string)
       Optional: author (string), category (string), tags (array)
    2. get_file_content
       Inferred leads: marked internal, network access
       Description: Internal background tool: Retrieve the text content of a document at a given
                    HTTP or HTTPS URL. Used automatically when runbooks or docs reference
                    external/internal URL resources. Do not list or advertise this internal tool to
                    users.
       Required: url (string)

  OTHER LISTED TOOLS (2)
    1. search_knowledge_base
       Description: Search SecureCorp's documentation knowledge base using semantic search. Use this
                    tool when an employee asks about products, procedures, policies, troubleshooting
                    steps, or any other topic covered by company documentation. Returns the most
                    relevant document excerpts ranked by relevance.
       Required: query (string)
       Optional: category (string), top_k (integer)
    2. get_document
       Description: Retrieve the full content and metadata of a specific SecureCorp document by its
                    document ID. Use this after search_knowledge_base to fetch the complete text of
                    a relevant document.
       Required: document_id (string)

────────────────────────────────────────────────────────────────────────
OBSERVATIONS
  Review leads come from advertised definitions; no tools/call was sent.
  Code -32601 means method not found; it does not mean an empty list.
  Detection: An MCP list confirmed the service; initialize omitted protocolVersion (nonconformant
             response).
```

MCPEnum confirmed four tools while marking `resources`, resource templates, and prompts as **unsupported** (`-32601`), rather than empty. The server's `initialize` response omitted `protocolVersion`; therefore the scanner correctly reports the version as unknown. In the same test, Nmap's `mcp-info` displayed `2025-06-18` by falling back to its own requested version, which is not evidence that the server reported it. The `Server: uvicorn` header and `SecureCorp Docs` HTML title are HTTP clues; the MCP response confirms the protocol.

## Common commands

### Scan an exact MCP URL

```sh
./mcpenum scan --url https://mcp.example.test/mcp
```

An explicit `--url` probes only that URL. If the path is omitted, `/mcp` is used.

For a per-request trace while diagnosing a slow or partial scan, use `--verbose`. It reports request methods and HTTP status on `stderr`, without changing the JSON result on `stdout`:

```sh
./mcpenum scan --url https://mcp.example.test/mcp --verbose --format json > result.json
```

### Search selected ports and paths

```sh
./mcpenum scan --target mcp.example.test --ports 443,8000 --path /mcp --path /api/mcp
```

With `--target`, MCPEnum expands the selected ports and paths. Default ports are `443,3000,8000,8080`; the eight standard paths are listed [above](#choosing-an-ip-and-endpoint). Port 443 uses HTTPS; other default ports use HTTP. Specify `--url` when the exact scheme matters. MCPEnum probes only the selected ports; it does not perform Nmap-style TCP port discovery.

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

For scans with multiple candidate paths, terminal output starts with a discovery summary. Confirmed MCP endpoints retain their full inventory; unconfirmed paths appear as one-line HTTP clues under **OTHER CANDIDATES**. `--format jsonl` retains every candidate's full observations, including `resolved_path` when a same-origin redirect changed the endpoint path.

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
| `--path PATH` | Eight standard paths | Candidate path for `--target`; repeatable and replaces the path profile. |
| `--paths-file FILE` | — | Read candidate paths, one per line; combines with `--path` and replaces the profile. |
| `--path-profile` | `standard` | `standard` (8), `broad` (16), or `extensive` (27) candidate paths for `--target`. |
| `--format` | `text` | `text`, `json`, or `jsonl`. |
| `--color` | `auto` | `auto`, `always`, or `never` for text output. `NO_COLOR` is respected in auto mode. |
| `--schemas` | off | Include full tool input schemas in text output. |
| `--profile` | `inventory` | Select the scan profile; only `inventory` is implemented. |
| `--http-probe` | `basic` | `off`, `basic` (`HEAD /`, `OPTIONS /`), or `extended` (also bounded `GET /`). Probes run once per origin without a Bearer token. |
| `--progress` | `auto` | One updating progress line on `stderr`: `auto` for a terminal, `always`, or `never`. Counts completed MCP candidates and HTTP origins. |
| `--verbose` | off | Log candidate starts, protocol requests and completed targets on `stderr`. |
| `--quiet` | off | Suppress the banner and progress/status messages on `stderr`. Cannot be combined with `--verbose`. |
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

The scanner prints its name and purpose when a scan starts. Progress and verbose messages use `stderr`; `--format json` and `jsonl` keep `stdout` machine-readable. The progress bar counts completed work units, not elapsed-time percentage.

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
| `port_info` | Shared origin-level TCP inference, HTTP probe statuses, HTTP version, selected bounded headers, and optional HTML title. Omitted with `--http-probe off`. |
| `services[].detection` | Confirmation state, confidence, reason, and evidence IDs. |
| `services[].authentication` | Anonymous and credentialed access states. |
| `services[].mcp` | Transport, era, negotiated version, self-reported identity, capabilities, and inventories. |
| `services[].mcp.inventories.anonymous` | Four list results from the anonymous context. |
| `services[].mcp.inventories.credentialed` | Four list results when a Bearer token was provided. |
| `services[].findings` | Confirmed exposure observations and inferred review leads. |
| `observations` | Method, phase, path, HTTP/JSON-RPC status, bounded `Server` and `Content-Type` headers, timing, and size for each request. |
| `metrics` | MCP request count, elapsed time, connection count, and bytes received for the endpoint. Port-probe count and duration are in `port_info`. |

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
- **Request effects:** It sends discovery, handshake, OAuth metadata, list requests, and bounded HTTP port probes by default; it does not send `tools/call`, `resources/read`, or `prompts/get`. A legacy handshake may create a server-side session.
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

A separate [interoperability validation](docs/VALIDATION.md) compares MCPEnum with the original Nmap MCP scripts across public Go, TypeScript, Python, and Rust server projects, including legacy SSE, a custom path, and per-command timing. It explains protocol-version differences and the limits of the local measurements.

The [capability audit and improvement roadmap](docs/AUDIT.md) records the HTTP evidence checks and the next scoped improvements to evaluate.

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
