# Local interoperability validation

This report records local scans performed on 2026-10-25 against servers built from distinct public MCP projects. It compares MCPEnum with the `mcp-info` and `mcp-enum` scripts from [`nmap-ai-recon` at `86e94bd`](https://github.com/insidetrust/nmap-ai-recon/tree/86e94bda9dbb1defc4aed61adb4b67b80e422c43). All scans targeted `127.0.0.1`; no third-party deployment was scanned.

The comparison has two parts: inventory correctness and endpoint discovery. Counts are reported as **tools / resources / resource templates / prompts** for MCPEnum. The Nmap scripts display resource templates together with resources, so their resource count is a combined value. Both clients can negotiate different MCP revisions with the same server; compare inventories only in that context.

## Projects and fixtures

| Project | Source used | Local configuration |
|---|---|---|
| [mark3labs/mcp-go](https://github.com/mark3labs/mcp-go/blob/84ad98e6bb81de968065a26c14dfb257c37e1915/examples/everything/main.go) | `84ad98e` `examples/everything` | Bind changed to `127.0.0.1:14001`; `/mcp`. |
| [MCP TypeScript servers](https://github.com/modelcontextprotocol/servers/tree/ef9808f71090d0db3eda99e2af2ba78f1086f4fb/src/everything) | `ef9808f` `src/everything` | Official HTTP example on `:14002/mcp` and SSE example on `:14003/sse`; built with Node 24. |
| [FastMCP](https://github.com/PrefectHQ/fastmcp/tree/6d665f0f8d2707609b9d77b2671f93e439ff2352) | FastMCP 4.1.3 | Small local fixture with one tool, resource, and prompt, served at `:14004/api/v1/mcp`. |
| [MCP Rust SDK](https://github.com/modelcontextprotocol/rust-sdk/blob/8aec3891dd07fc537b21c2eb2596235640de9025/examples/servers/src/counter_streamhttp.rs) | `8aec389` counter Streamable HTTP example | Bind changed to `127.0.0.1:14005`; `/mcp`. |
| MCP Python SDK v2 | Existing local control fixture | One tool and one resource at `:13004/mcp`; included to check continuity with earlier tests. |

Only bind addresses were changed in the upstream Go and Rust examples. The FastMCP fixture declared `lookup_note`, `demo://status`, and `summarize_note`, then called `mcp.run(transport="http", host="127.0.0.1", port=14004, path="/api/v1/mcp")`.

## Exact-endpoint results

These are single wall-clock measurements on one local machine, including each command's process startup. They are **not network benchmarks**. Nmap used `-Pn -n` without `-sV` here so its general port-version fingerprinting would not dominate the MCP script comparison. `mcp.allports=true` enabled the scripts on the chosen nonstandard ports.

| Server | MCPEnum MCP version | MCPEnum T / R / RT / P | Nmap MCP version | Nmap T / R+RT / P | MCPEnum / Nmap wall time |
|---|---|---:|---|---:|---:|
| mcp-go HTTP | `2026-07-28` | 6 / 101 / 1 / 2 | `2025-06-18` | 6 / 102 / 2 | 22 / 253 ms |
| TypeScript HTTP | `2026-07-28` | 22 / 7 / 3 / 4 | `2025-06-18` | 16 / 9 / 4 | 33 / 232 ms |
| TypeScript SSE | `2025-11-25` | 16 / 7 / 2 / 4 | `2025-06-18` | 16 / 9 / 4 | 17 / 275 ms |
| FastMCP custom route | `2026-07-28` | 1 / 1 / 0 / 1 | `2025-06-18` | 1 / 1 / 1 | 24 / 256 ms |
| Rust SDK HTTP | `2026-07-28` | 8 / 2 / 0 / 2 | `2025-06-18` | 8 / 2 / 2 | 18 / 277 ms |
| Python SDK v2 control | `2026-07-28` | 1 / 1 / 0 / 0 | `2025-06-18` | 1 / 1 / 0 | 11 / 213 ms |

All four MCPEnum inventory collections (`tools`, `resources`, `resource_templates`, `prompts`) finished with `complete` or `empty` in these cases. Nmap confirmed all six exact endpoints. The observed tool names matched where the clients negotiated the same era, after stripping Nmap's added risk annotations from display names. Neither scanner called any tool or read a resource.

The TypeScript HTTP tool-count difference is expected, not a missed list page: [its source registers tools by protocol era](https://github.com/modelcontextprotocol/servers/blob/ef9808f71090d0db3eda99e2af2ba78f1086f4fb/src/everything/tools/index.ts). The current Nmap scripts offer `2025-06-18`; MCPEnum offers `2026-07-28`, so the server exposes 16 legacy tools to Nmap and 22 modern tools to MCPEnum. The TypeScript SSE transport used the older handshake with both clients. The resource count difference on mcp-go is exactly its one separately listed resource template.

The TypeScript SSE case also exposed a session-reporting gap in MCPEnum: the server returned `sessionId` in its SSE message URL, while MCPEnum initially displayed `session: unknown`. The scanner now marks this case `stateful` without printing the identifier. A regression test covers both a session-bearing URL and an SSE URL without a session signal. A fresh scan after the fix kept the same 16 / 7 / 2 / 4 inventory. Nmap had already displayed `stateful` for SSE, but its legacy transport code sets that label without checking for an `Mcp-Session-Id` response header; that header was absent in this server's SSE response.

Example commands for one exact endpoint:

```sh
./mcpenum scan --url http://127.0.0.1:14005/mcp --format json

nmap --datadir /path/to/nmap-ai-recon -Pn -n -p14005 \
  --script /path/to/nmap-ai-recon/scripts/mcp-info.nse,/path/to/nmap-ai-recon/scripts/mcp-enum.nse \
  --script-args 'mcp.paths=/mcp,mcp.allports=true' 127.0.0.1
```

Adding `-sV` makes Nmap show its general service fingerprint too. In these local runs it raised total time to roughly 6–12 seconds per confirmed endpoint, mostly due to version probing; that is a different workload from the MCP scripts alone.

## Unknown-path discovery

The FastMCP fixture's path, `/api/v1/mcp`, was not supplied to either scanner in the initial check:

| Search configuration | Candidates | Requests reported by MCPEnum | Found MCP? | Wall time |
|---|---:|---:|---|---:|
| MCPEnum `--path-profile standard` | 7 | 15 | No | 20 ms |
| MCPEnum `--path-profile broad` | 15 | 32 | No | 24 ms |
| MCPEnum `--path-profile extensive` | 27 | 61 | Yes, `/api/v1/mcp` | 45 ms |
| Nmap scripts, default paths | 15 | Not reported | No | 15,290 ms |

The missed FastMCP route was a useful coverage gap. MCPEnum now includes `/api/v1/mcp` in both the default and broad profiles. A fresh local check, again without an explicit path, produced:

| MCPEnum profile after fix | Candidates | Requests | Found MCP? | Wall time |
|---|---:|---:|---|---:|
| `standard` | 8 | 20 | Yes; 1 tool, 1 resource, 1 prompt | 24 ms |
| `broad` | 16 | 37 | Yes; 1 tool, 1 resource, 1 prompt | 30 ms |
| `extensive` | 27 | 61 | Yes; 1 tool, 1 resource, 1 prompt | 62 ms |

With `/api/v1/mcp` passed explicitly, Nmap confirmed the service and listed the same one tool, one resource, and one prompt. Its default path list remains unchanged. A missed default path must be reported as *not found within the chosen candidates*, never as proof that the host has no MCP endpoint. The broader MCPEnum profiles spend more requests to cover other nested and legacy paths; no profile can infer arbitrary private prefixes.

The first post-change text report classified the non-existent `/sse` candidate as `inconclusive` despite three HTTP 404 responses. That state was corrected: a modern discovery 404, legacy initialize 404, and SSE GET 404/405 now produce a completed negative candidate. A regression test and a repeat of the FastMCP default scan confirmed `MCP endpoints: 1 | inconclusive: 0`.

```sh
./mcpenum scan --target 127.0.0.1 --ports 14004
```

## Assessment and limits

MCPEnum produced complete, correctly separated inventories across the tested Go, TypeScript, Python, and Rust servers, including Streamable HTTP, legacy SSE, and a custom route. Its measured command time was lower than Nmap's in every local exact-endpoint run, but a single loopback run is insufficient to establish a general speed ratio. The protocol-version and TypeScript tool-count differences follow the servers' negotiated behavior. The SSE session-reporting, default-path coverage, and missing-SSE classification gaps were corrected and retested; no inventory-count defect was found in these fixtures.

This is inventory validation, not execution or vulnerability testing. It does not establish that listed tools are callable, that access controls are correct, or that the scanner covers every MCP implementation. Repeat the same checks on a new server version before relying on the counts. Keep `--url` or a scoped `--path` list for known routes; use `extensive` when the route is unknown and the extra requests fit the scan budget.
