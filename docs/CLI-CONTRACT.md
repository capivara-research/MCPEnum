# CLI and JSON contract (v0.2.0)

This page defines the public interface for scripts using MCPEnum. The first tagged release is `v0.1.0`; before v1.0, incompatible changes may occur between minor versions and are listed in [CHANGELOG.md](../CHANGELOG.md).

## Invocation and exit status

Run `mcpenum --target HOST[:PORT]` to discover MCP endpoints or `mcpenum --url URL` for an exact endpoint. The old positional `scan` subcommand is rejected. `mcpenum --help` and `mcpenum --version` do not contact a target.

| Exit code | Meaning |
|---:|---|
| 0 | CLI completed, including a negative scan or a report with partial per-target results. Inspect `scan_status` and collections. |
| 2 | Invalid options, target expansion failure, or another fatal scan error before a complete report could be written. |
| 130 | Interrupted by Ctrl-C; a complete report is not guaranteed. |

Progress, the banner, and verbose events go to `stderr`. The report alone goes to `stdout`. `--quiet` suppresses the banner and progress; `--progress never` suppresses the progress line while preserving the banner. Tokens are read from an environment variable or file and are never included in reports.

## JSON shape

`--format json` always emits an array of result objects, including for a single exact URL. `--format jsonl` emits one result object per line. Every result has `schema_version: "2.0"`, `scanner`, `target`, `scan_status`, `services`, `observations`, and `metrics`. `port_info` and `warnings` are optional. `services` and `observations` are arrays even when empty. `scan_status` is `completed`, `partial`, or `failed`.

`target.input` is the tested candidate URL for a confirmed HTTP(S) port. A selected port that fails HTTP identification produces one `failed` result whose `target.input` is the origin; it does not produce a result for every candidate path. `port_info.tcp_state` distinguishes closed from open TCP in selected-port mode. A bare host scans TCP ports 1–65535 by default; only open ports continue to HTTP identification. If no port is open, the scan returns one completed negative result for that host with a warning instead of a fatal CLI error. `--ports` selects up to 128 ports, and `--scan-ports START-END` overrides the range. `HOST:PORT` checks one port. `--no-port-scan` skips TCP/HTTP identification and requires explicit ports. An exact `--url` skips port discovery and candidate path expansion. Supplemental HTTP probes default to `off` for exact URLs and `--no-port-scan`; `--http-probe` can turn them on.

New optional fields may be added within schema 2.0. Existing field names and meanings remain stable for the v0.2 line. Consumers should ignore unknown fields and use `schema_version` to reject a major schema they do not understand. Enumerated status strings are documented in [the technical guide](TECHNICAL.md).

Example automation:

```sh
mcpenum --target 127.0.0.1:8000 --format json --quiet > report.json
jq '.[] | select(.services[]?.detection.status == "confirmed") | .target.input' report.json
```
