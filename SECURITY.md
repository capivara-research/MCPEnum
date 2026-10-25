# Security policy

MCPEnum handles untrusted server responses and optional Bearer tokens. Please report vulnerabilities that may expose credentials, cross target boundaries, hang indefinitely, or allow terminal control sequences to affect the operator's display.

Use GitHub's **Report a vulnerability** private reporting feature for this repository when available. Include the affected version, a minimal local reproducer, expected behavior, observed behavior, and whether a token was configured. Do not include real credentials in the report.

The default scan is read-only at the MCP tool level: it never sends `tools/call`. A successful anonymous `tools/list` is an inventory result, not proof that tool execution is anonymous.
