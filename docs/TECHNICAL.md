# How MCPEnum performs a scan

This document explains what a default `mcpenum` run does on the wire and how to interpret its evidence. The scanner sends no MCP tool calls.

## 1. Choose endpoints

`--url` uses the URL exactly as supplied, adding `/mcp` only when there is no path. `--target` checks selected TCP ports, identifies HTTP(S), then tests candidate paths on those ports. A user can provide only `host:port` when the endpoint is unknown. For an unknown port, `--scan-ports START-END` checks an explicit TCP range first. Automatic TLS detection works on nonstandard ports; `--scheme http` or `--scheme https` overrides it without changing exact `--url` inputs. The path profiles contain 9 (`standard`), 17 (`broad`, the default), or 28 (`extensive`) candidates. The default includes all 15 paths from `nmap-ai-recon` at `86e94bd`, `/api/v1/mcp`, and `/mcp/transport` from SecLists’ [`mcp-server.txt`](https://github.com/danielmiessler/SecLists/blob/ab068333d7d44a9376e2037b0ed7d2e8ca5c6610/Discovery/Web-Content/mcp-server.txt). The candidate is curated into MCPEnum; SecLists is not a runtime dependency. Supplying `--path` or `--paths-file` replaces the profile with explicit paths; the two custom sources combine. Custom paths are capped at 128 entries and 256 bytes each. Explicit URLs and expanded targets are deduplicated. CIDR expansion is disabled until `--allow-cidr` is supplied, and `--max-hosts` caps it.

Each endpoint receives its own time budget. Multiple endpoints can run concurrently, bounded by `--workers`. `--rate` caps aggregate HTTP request rate across the scan.

Before MCP path requests, target discovery sends bounded `HEAD /` and `OPTIONS /` on each open TCP port to confirm HTTP and collect metadata. These requests occur even with `--http-probe off`, because protocol identification is required before endpoint enumeration. Exact `--url` inputs bypass this preflight. After MCP collection, exact URLs and other origins not already profiled receive the default `basic` HTTP profile with `HEAD /` and `OPTIONS /`. `--http-probe extended` also sends `GET /` with `Range: bytes=0-4095`, reads at most 4096 bytes, and extracts an HTML title when present. `--http-probe off` skips supplemental post-scan profiling. Each probe has a maximum 1500 ms timeout (or the lower configured request timeout), a 16 KiB response-header cap, and no redirect following. The configured Bearer token is not sent. Redirect query strings are removed from reported locations. `port_info` reports the HTTP status, protocol, selected bounded headers, TLS version when observed, and probe duration. It is repeated in each JSONL candidate record for self-contained processing, although network requests occur only once per origin. The per-endpoint `metrics.requests` count excludes these shared probes. These are valid HTTP methods under [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110.html); they are not a replacement for [Nmap's general service-version probes](https://nmap.org/book/vscan-examples.html).

## 2. Identify the protocol era

MCPEnum first sends `server/discover` with the `2026-07-28` protocol metadata. A valid modern response confirms MCP and supplies capabilities and, when present, server identity. The scanner then sends list requests with modern request metadata. It does not send `initialize` after a successful modern discovery.

If modern discovery does not confirm the endpoint, MCPEnum sends one legacy `initialize` offer for `2025-11-25`. A conforming server can answer with an older supported revision; MCPEnum records that returned version and uses it for later requests. If the server returns the MCP `UnsupportedProtocolVersion` error with a supported-version offer, MCPEnum can retry with one of the listed handshake revisions. On successful initialization it sends `notifications/initialized` before listing.

A server can return a plausible `initialize` shape with no protocol version or a nonstandard version. MCPEnum only confirms such a server after a valid `tools/list` response. If that list fails, detection remains inconclusive. This is useful for training servers and custom bridges without treating every JSON response as confirmed MCP.

For legacy HTTP+SSE endpoints, MCPEnum uses the event stream and message endpoint when the candidate path ends in `/sse` (for example `/sse`, `/api/sse`, or `/mcp/sse`). It still applies the same response and time limits.

## 3. List inventory

For each confirmed endpoint and access context, MCPEnum requests:

1. `tools/list`
2. `resources/list`
3. `resources/templates/list`
4. `prompts/list`

When a response contains `nextCursor`, the corresponding method is called again with that cursor. Duplicate items are removed, repeated cursors stop the loop, and `--max-pages` and `--max-items` bound the inventory. One list failing does not turn another successful list into a failure.

Collection states have specific meanings:

| State | Meaning |
|---|---|
| `complete` | One or more valid items were listed, and pagination ended. |
| `empty` | The method succeeded and returned a valid empty list. |
| `partial` | Some data was obtained, but a configured limit or repeated cursor prevented completion. |
| `unsupported` | The server returned method-not-found (`-32601`). |
| `denied` | Access to that list was refused. |
| `timeout` | The time budget expired while listing. |
| `error` | A transport, HTTP, JSON-RPC, or collection-shape error prevented a reliable result. |
| `not_tested` | No request for that collection was made. |

In text output, `error` is displayed as `failed`. In JSON, the original state is kept as `error`. Error codes are shown when available. A method-not-found response does not mean the collection is empty.

## 4. Compare access contexts

Without a token, only the anonymous context is scanned. With `--token-env` or `--token-file`, MCPEnum scans anonymously first, then sends the Bearer token to the same endpoint and records a separate credentialed inventory. The presence of a supplied token does not make the anonymous result authenticated. OAuth protected-resource metadata is fetched only when linked to the target origin; authorization servers are reported, not visited automatically.

MCPEnum does not call tools. A tool can be listed anonymously while `tools/call` requires authentication or fails for other reasons. The `Tool execution` line is therefore always `not tested` in the current release.

## 5. Produce review leads

Tool names, descriptions, and bounded-depth input schemas are examined for indicators such as paths, URLs, SQL terms, process execution terms, state-changing verbs, environment variables, terminal display control options, invisible characters, and instructions aimed at an assistant. The matching source is recorded as a path such as `tools[fetch_url].inputSchema.properties.url`.

These are **inferred** leads for a human reviewer. They do not establish that a tool will run, that it can cross an authorization boundary, or that a specific vulnerability exists. Descriptions supplied by a server can be wrong or malicious.

Terminal text escapes control characters that could otherwise hide content or manipulate the display. The JSON format preserves the original inventory values so downstream tools can inspect raw metadata.

## 6. Record evidence and limits

The JSON result contains a `services` array, `observations`, `port_info`, and `metrics`. Observations record the phase, MCP method, path, HTTP status, JSON-RPC status or code, elapsed time, and response size. Bounded HTTP `Server` and `Content-Type` response headers are also recorded, so a non-MCP HTTP candidate can still provide a service clue. `port_info` adds separate port-level HTTP responses. `resolved_path` records a same-origin redirect's final path when it differs from the candidate; confirmed service identity uses that final path. A header is self-reported and does not prove a product or version. Findings and collections refer to observations by evidence ID. Bearer tokens and session IDs are not included in output.

For multi-candidate text scans, MCPEnum prints a summary, one full inventory per distinct confirmed endpoint, and compact rows for other candidates. Redirect aliases are shown without repeating the same inventory. JSON/JSONL preserves every candidate result for audit and automation.

MCPEnum uses a per-request timeout, a per-endpoint budget, a maximum response body size, and inventory page and item caps. HTTPS certificate verification is enabled by default. HTTP redirects are restricted to the original target origin. `--insecure` is an explicit opt-in for test environments with untrusted certificates.

## What is outside the current release

The current release does not launch stdio servers, call tools, read resources, render prompts, execute payloads, or verify CVEs. It discovers and inventories HTTP-accessible MCP servers and preserves uncertainty in its results.
