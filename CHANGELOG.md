# Changelog

## v0.2.0 - 2026-10-25

- Make `mcpenum --target HOST` discover TCP ports 1–65535 by default, then test MCP candidates on every HTTP(S) port found.
- Keep `HOST:PORT`, `--ports`, `--scan-ports`, and exact `--url` for scoped workflows; add `--no-port-scan` to test paths directly on selected ports.
- Summarize confirmed MCP endpoints for each HTTP port in text output.
- Bound the default full sweep with 256 workers, 500 TCP connections per second, and a retry for transient connection errors.
- Report client version 0.2.0 in the User-Agent and MCP client metadata.

## v0.1.0 - 2026-10-25

- Accept scan flags directly after `mcpenum`; remove the `scan` subcommand.
- Add `mcpenum --version` with Go build and source revision information.
- Remove the unused `--profile` flag; `inventory` remains the scan behavior.
- Add `--scan-ports START-END` for optional TCP discovery, then confirm HTTP(S) before MCP path tests. Detect TLS on nonstandard ports; `--scheme` can override detection.
- Use conservative default pacing (`--rate 20`, `--workers 8`) and bound port and candidate expansion.
- Make `--format json` always emit an array; document JSON schema 2.0 and exit codes.
- Add race detection, parser fuzzing, vulnerability checks, pinned Actions workflows, FastMCP interoperability CI, and cross-platform release archives with checksums and provenance attestations.
- Require Go 1.27.3 for builds to include current standard-library security fixes.

Earlier changes are recorded in the Git history.
