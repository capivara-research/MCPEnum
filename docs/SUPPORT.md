# Supported and tested configurations

MCPEnum builds with Go 1.27.3 or newer. CI runs on the Go version declared in `go.mod` and performs unit tests, the race detector, parser fuzzing, vet, and govulncheck. A separate CI matrix starts local FastMCP `3.4.11` and `4.1.3` servers on a custom HTTP path and checks discovery plus tool inventory. Release archives are built for Linux amd64/arm64, macOS amd64/arm64, and Windows amd64. Other Go-supported platforms can build from source.

The scanner handles HTTP-accessible Streamable HTTP and legacy HTTP+SSE. Protocol tests cover the MCP revisions `2024-11-05`, `2025-03-26`, `2025-06-18`, and the newer `server/discover` exchange used by supported fixtures. It does not launch stdio servers. [Validation notes](VALIDATION.md) distinguish automated tests from manual Go, TypeScript, Python, and Rust SDK checks; only the pinned FastMCP versions run as external SDK servers on every CI change.

CLI changes follow [Semantic Versioning 2.0](https://semver.org/) from the first `v0.1.0` release; the public contract is [documented here](CLI-CONTRACT.md). During v0.x, minor releases may change the CLI or JSON schema and will call out migration steps in the changelog.
