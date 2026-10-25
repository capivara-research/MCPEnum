# CLI and JSON contract (v0.1.0)

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

`target.input` is the tested candidate URL for a confirmed HTTP(S) port. A closed port or an open port without a valid HTTP response produces one `failed` result whose `target.input` is the origin; it does not produce a result for every candidate path. `port_info.tcp_state` distinguishes closed from open TCP. The default checks six common ports; `--ports` selects up to 128, and `--scan-ports START-END` optionally checks a wider TCP range. An exact `--url` skips TCP and HTTP preflight.

New optional fields may be added within schema 2.0. Existing field names and meanings remain stable for the v0.1 line. Consumers should ignore unknown fields and use `schema_version` to reject a major schema they do not understand. Enumerated status strings are documented in [the technical guide](TECHNICAL.md).

Example automation:

```sh
mcpenum --target 127.0.0.1:8000 --format json --quiet > report.json
jq '.[] | select(.services[]?.detection.status == "confirmed") | .target.input' report.json
```
