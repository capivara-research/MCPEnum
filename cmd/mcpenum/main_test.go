package main

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/capivara-research/MCPEnum/internal/mcprecon"
)

func TestTerminalOutputShowsActionableInventory(t *testing.T) {
	result := mcprecon.Result{
		Target:     mcprecon.Target{Input: "http://lab.test/mcp"},
		ScanStatus: "completed",
		Metrics:    mcprecon.Metrics{Requests: 6, DurationMS: 1200},
		Services: []mcprecon.Service{{
			Endpoint:       "/mcp",
			Detection:      mcprecon.Detection{Status: "confirmed", Confidence: "high"},
			Authentication: mcprecon.Authentication{Anonymous: "accepted", Credentialed: "not_tested"},
			MCP: mcprecon.MCP{Transport: "streamable_http", Era: "legacy", Session: "stateful", ServerName: "fixture", Capabilities: map[string]any{"tools": map[string]any{}}, Inventories: map[string]mcprecon.Collections{
				"anonymous": {Tools: mcprecon.Collection{Status: "complete", Count: 2, EvidenceIDs: []string{"e1"}, Items: []map[string]any{{"name": "fetch_url", "description": "Fetch a URL", "inputSchema": map[string]any{"type": "object", "properties": map[string]any{"url": map[string]any{"type": "string"}}, "required": []any{"url"}}}, {"name": "health_check", "description": "Return health status"}}}, Resources: mcprecon.Collection{Status: "unsupported", ErrorCode: "-32601"}, ResourceTemplates: mcprecon.Collection{Status: "not_tested"}, Prompts: mcprecon.Collection{Status: "not_tested"}},
			}},
			Findings: []mcprecon.Finding{{Code: "tool_hint_network", Category: "network", SourcePath: "tools[fetch_url].name", Status: "inferred", EvidenceIDs: []string{"e1"}}, {Code: "public_tools", Summary: "2 tools listed anonymously", Status: "confirmed"}},
		}},
	}
	var out bytes.Buffer
	printResult(&out, result, false)
	got := out.String()
	for _, expected := range []string{"Summary: MCP confirmed | anonymously listed tools: 2 (complete) | review leads: 1", "IDENTIFICATION", "ACCESS", "INVENTORY ANONYMOUS", "Session: session ID present", "Advertised capabilities: tools", "Anonymous listing: accepted", "Tools listed anonymously: 2", "TOOLS WITH REVIEW LEADS (1)", "Inferred leads: network access", "Required: url (string)", "OTHER LISTED TOOLS (1)", "unsupported [-32601]", "Code -32601 means method not found; it does not mean an empty list.", "no tools/call was sent"} {
		if !strings.Contains(got, expected) {
			t.Errorf("missing %q in output:\n%s", expected, got)
		}
	}
	if strings.Contains(got, "Schema:") {
		t.Fatal("full schema should be opt-in")
	}
	if strings.Contains(got, "\x1b[") {
		t.Fatal("plain output contains ANSI codes")
	}
	if count := strings.Count(got, strings.Repeat("─", 72)); count != 4 {
		t.Fatalf("expected four section dividers, got %d", count)
	}
	out.Reset()
	printResult(&out, result, true)
	if !strings.Contains(out.String(), "Schema:") {
		t.Fatal("--schemas should print schema")
	}
	out.Reset()
	printResultStyled(&out, result, false, true)
	if !strings.Contains(out.String(), "\x1b[1;33mIDENTIFICATION\x1b[0m") || !strings.Contains(out.String(), "\x1b[1;33mACCESS\x1b[0m") || !strings.Contains(out.String(), "\x1b[1;33mINVENTORY ANONYMOUS\x1b[0m") || !strings.Contains(out.String(), "\x1b[1;33mOBSERVATIONS\x1b[0m") {
		t.Fatal("colored section headings missing")
	}
}

func TestTerminalColorModes(t *testing.T) {
	var out bytes.Buffer
	if terminalColorEnabled("auto", &out) || terminalColorEnabled("never", os.Stdout) {
		t.Fatal("unexpected color in auto non-terminal or never mode")
	}
	if !terminalColorEnabled("always", &out) {
		t.Fatal("always mode should force colors")
	}
}

func TestTerminalUnconfirmedShowsProbeEvidence(t *testing.T) {
	result := mcprecon.Result{
		Target:     mcprecon.Target{Input: "http://lab.test/not-mcp"},
		ScanStatus: "completed",
		Observations: []mcprecon.Observation{
			{Phase: "discovery", Method: "server/discover", HTTPStatus: 404, ErrorCode: "unexpected_content_type"},
			{Phase: "discovery", Method: "initialize", HTTPStatus: 404, ErrorCode: "unexpected_content_type"},
		},
	}
	var out bytes.Buffer
	printResult(&out, result, false)
	got := out.String()
	for _, expected := range []string{"Summary: MCP not confirmed", "PROBE OBSERVATIONS", "server/discover: HTTP 404 (unexpected_content_type)", "initialize: HTTP 404 (unexpected_content_type)", "try authorized alternate paths"} {
		if !strings.Contains(got, expected) {
			t.Errorf("missing %q in output:\n%s", expected, got)
		}
	}
}

func TestSafeDescriptionRevealsHiddenControls(t *testing.T) {
	got := safeDescription("before\x1b[8mhidden\x1b[0m\u200bafter")
	if !strings.Contains(got, `\x1b[8m`) || !strings.Contains(got, `\u200b`) || strings.ContainsRune(got, '\x1b') || strings.ContainsRune(got, '\u200b') {
		t.Fatalf("hidden controls not escaped safely: %q", got)
	}
}

func TestToolHintsStayWithTheirInventory(t *testing.T) {
	findings := []mcprecon.Finding{{Code: "tool_hint_network", Category: "network", SourcePath: "tools[shared].inputSchema.properties.url", EvidenceIDs: []string{"credentialed-list"}}}
	if got := toolHints("shared", findings, []string{"anonymous-list"}); len(got) != 0 {
		t.Fatalf("anonymous list inherited credentialed hint: %v", got)
	}
	if got := toolHints("shared", findings, []string{"credentialed-list"}); len(got) != 1 || got[0] != "network" {
		t.Fatalf("credentialed hint missing: %v", got)
	}
}
