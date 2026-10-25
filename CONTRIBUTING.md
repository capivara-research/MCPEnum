# Contributing to MCPEnum

Thanks for improving MCPEnum. Please keep changes focused on accurate, bounded, read-only MCP reconnaissance.

## Before opening a pull request

1. Describe the MCP server behavior or the output problem with a small reproducible example.
2. Add a test when the change affects protocol negotiation, parsing, pagination, classification, or output semantics.
3. Run `go test ./...`, `go test -race ./...`, `go vet ./...`, and `go build -o mcpenum ./cmd/mcpenum`.
4. Update the README and changelog when flags, output, defaults, or limitations change.

Use local fixtures for tests. Tests should not contact public services. A metadata review lead must stay distinguishable from confirmed protocol evidence or a confirmed vulnerability. Do not add active `tools/call` checks to the default inventory scan.

For security issues, follow [SECURITY.md](SECURITY.md) instead of filing a public issue.
