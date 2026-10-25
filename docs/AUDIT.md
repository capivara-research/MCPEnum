# MCPEnum capability audit — 2026-10-25

## Scope and evidence

This review compares MCPEnum with Nmap service detection and the OWASP Web Security Testing Guide's web-server fingerprinting guidance. The local comparison used `127.0.0.1:13000/mcp`; it is not a benchmark for external networks.

- `go test -race ./...` and `go vet ./...` passed during the review.
- MCPEnum confirmed MCP and listed 12 tools, 3 resources, and 2 prompts on the local training target. Nmap 7.99 with `-sV`, `mcp-info`, and `mcp-enum` listed the same counts.
- MCPEnum's extended HTTP profile observed `HEAD /` → 404, `OPTIONS /` → 204, and `GET /` → 404; the GET response contained the HTML title `Error`. These responses are separate from MCP protocol evidence.
- Nmap `-sV` identified `mcp vulnerable-mcp-server 1.0.0`. MCPEnum does not claim to reproduce Nmap's service-signature database.

## Improvements implemented

| Need | Implementation and interpretation |
|---|---|
| Keep evidence separate from conclusions | HTTP status and headers do not confirm MCP. The detector still requires a valid protocol response; `port_info` is separate from the MCP inventory. |
| Bound cost | `off`, `basic`, and `extended` HTTP profiles; one probe set per origin; per-request timeout, response-header limit, and at most 4 KiB read for an HTML title. |
| Handle redirects safely | Port probes do not follow redirects. Reported `Location` values omit query strings and fragments. |
| Protect credentials | The configured Bearer token is not sent in origin-level HTTP probes. Output uses error categories and bounded header values. |
| Keep reports usable | Terminal output prints one port profile per origin; JSONL keeps a self-contained copy per candidate. Banner and progress/verbose status go to `stderr`. |
| Preserve uncertainty | `open`, `closed`, and `unknown` reflect observed HTTP responses or connection refusal. Product and version headers remain self-reported clues. |

## Next opportunities

1. **HTTP/TLS identification on nonstandard ports.** Implemented: bare-host scans check all TCP ports by default, detect TLS, and confirm HTTP before MCP paths. `--scan-ports` narrows the range; `--no-port-scan` bypasses identification for a known service. Remaining work: tune identification for servers that reject both `HEAD /` and `OPTIONS /` before any valid MCP request, and measure false negatives on more SDKs.
2. **Hostnames with multiple addresses.** A full scan currently resolves a hostname during TCP connects and again during HTTP requests. Pinning one resolved address throughout each port's checks would avoid DNS churn and ambiguity when records differ. Until then, use an IP target for a precise host-level result.
3. **Service signatures with provenance.** If product/version signatures are added, report the matching response, rule, and confidence. A lone `Server` header must remain self-reported evidence.
4. **Non-HTTP services.** An open TCP port without HTTP should remain an unknown service. Generic banner detection would need a separate bounded module rather than an inference from a failed HTTP request.
5. **Continuous interoperability tests.** Keep fixtures for modern and legacy MCP, authentication, pagination, SSE, custom paths, redirects, and non-MCP HTTP services. Compare items and collection states as well as counts.
6. **Whole-scan performance accounting.** The new `port_info` records probe count and duration separately, preserving comparable MCP metrics. A benchmark should also record tool version, configuration, and lab latency.

## Sources

- [Nmap service and version detection](https://nmap.org/book/man-version-detection.html)
- [Nmap service probes](https://nmap.org/book/nmap-service-probes.html)
- [Nmap XML service method and confidence](https://nmap.org/book/output-formats-xml-output.html)
- [OWASP WSTG: Fingerprint Web Server](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server/)
