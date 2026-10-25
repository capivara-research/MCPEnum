package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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

func TestPathsFileFindsCustomMountedEndpoint(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     int    `json:"id"`
			Method string `json:"method"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if r.URL.Path != "/tenant/notes/mcp" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		result := map[string]any{}
		switch req.Method {
		case "server/discover":
			result = map[string]any{"supportedVersions": []string{"2026-07-28"}, "capabilities": map[string]any{"tools": map[string]any{}}}
		case "tools/list":
			result = map[string]any{"tools": []any{map[string]any{"name": "notes_search"}}}
		case "resources/list":
			result = map[string]any{"resources": []any{}}
		case "resources/templates/list":
			result = map[string]any{"resourceTemplates": []any{}}
		case "prompts/list":
			result = map[string]any{"prompts": []any{}}
		default:
			t.Errorf("unexpected method %q", req.Method)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": result})
	}))
	defer s.Close()
	file := filepath.Join(t.TempDir(), "paths.txt")
	if err := os.WriteFile(file, []byte("# custom deployment\n/tenant/notes/mcp\n"), 0600); err != nil {
		t.Fatal(err)
	}
	var out, errout bytes.Buffer
	if err := run([]string{"scan", "--target", strings.TrimPrefix(s.URL, "http://"), "--paths-file", file, "--format", "json"}, &out, &errout); err != nil {
		t.Fatal(err)
	}
	var result mcprecon.Result
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Services) != 1 || result.Services[0].Detection.Status != "confirmed" || result.Services[0].MCP.Inventories["anonymous"].Tools.Count != 1 {
		t.Fatalf("custom path not enumerated: %+v", result)
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

func TestProgressAndVerboseKeepJSONMachineReadable(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer s.Close()
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"progress", []string{"--progress", "always"}, "MCP candidates ["},
		{"verbose", []string{"--verbose"}, "[1/1]"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out, errout bytes.Buffer
			args := append([]string{"scan", "--url", s.URL + "/missing", "--http-probe", "off", "--format", "json"}, tc.args...)
			if err := run(args, &out, &errout); err != nil {
				t.Fatal(err)
			}
			var result mcprecon.Result
			if err := json.Unmarshal(out.Bytes(), &result); err != nil {
				t.Fatalf("stdout is not valid JSON: %v; output=%q", err, out.String())
			}
			if !strings.Contains(errout.String(), "MCPEnum") || !strings.Contains(errout.String(), tc.want) {
				t.Fatalf("missing banner or status on stderr: %q", errout.String())
			}
			if tc.name == "verbose" && !strings.Contains(errout.String(), "REQUEST") {
				t.Fatalf("verbose mode did not report protocol requests: %q", errout.String())
			}
		})
	}
	var out, errout bytes.Buffer
	if err := run([]string{"scan", "--url", s.URL + "/missing", "--http-probe", "off", "--format", "json", "--quiet", "--progress", "always"}, &out, &errout); err != nil {
		t.Fatal(err)
	}
	if errout.Len() != 0 {
		t.Fatalf("quiet mode wrote to stderr: %q", errout.String())
	}
}

func TestTerminalUnconfirmedShowsProbeEvidence(t *testing.T) {
	result := mcprecon.Result{
		Target:     mcprecon.Target{Input: "http://lab.test/not-mcp"},
		ScanStatus: "completed",
		Observations: []mcprecon.Observation{
			{Phase: "discovery", Method: "server/discover", HTTPStatus: 404, HTTPServer: "uvicorn", ContentType: "text/plain", ErrorCode: "unexpected_content_type"},
			{Phase: "discovery", Method: "initialize", HTTPStatus: 404, ErrorCode: "unexpected_content_type"},
		},
	}
	var out bytes.Buffer
	printResult(&out, result, false)
	got := out.String()
	for _, expected := range []string{"Summary: MCP not confirmed", "PROBE OBSERVATIONS", "server/discover: HTTP 404 (unexpected_content_type) | server: uvicorn | content-type: text/plain", "initialize: HTTP 404 (unexpected_content_type)", "try authorized alternate paths"} {
		if !strings.Contains(got, expected) {
			t.Errorf("missing %q in output:\n%s", expected, got)
		}
	}
}

func TestMultipleCandidatesKeepConfirmedDetailAndCompactMisses(t *testing.T) {
	portInfo := &mcprecon.PortInfo{Origin: "http://lab.test", TCPState: "open", Probes: []mcprecon.HTTPProbeInfo{{Method: "HEAD", Path: "/", Status: 404, Protocol: "HTTP/1.1", PoweredBy: "fixture-http"}}}
	confirmed := mcprecon.Result{
		Target:     mcprecon.Target{Input: "http://lab.test/mcp"},
		ScanStatus: "completed",
		PortInfo:   portInfo,
		Services: []mcprecon.Service{{
			Endpoint:  "/mcp",
			Detection: mcprecon.Detection{Status: "confirmed", Confidence: "high"},
			MCP:       mcprecon.MCP{Inventories: map[string]mcprecon.Collections{}},
		}},
	}
	miss := mcprecon.Result{
		Target:       mcprecon.Target{Input: "http://lab.test/api/mcp"},
		ScanStatus:   "completed",
		PortInfo:     portInfo,
		Observations: []mcprecon.Observation{{Phase: "discovery", Method: "initialize", HTTPStatus: 404, HTTPServer: "fixture-http"}},
	}
	var out bytes.Buffer
	printResultsStyled(&out, []mcprecon.Result{confirmed, miss}, false, false)
	got := out.String()
	for _, expected := range []string{"DISCOVERY SUMMARY  candidates: 2 | MCP endpoints: 1", "IDENTIFICATION", "OTHER CANDIDATES", "http://lab.test/api/mcp — MCP not confirmed | HTTP 404 | server: fixture-http", "Full per-candidate evidence: --format jsonl"} {
		if !strings.Contains(got, expected) {
			t.Errorf("missing %q in output:\n%s", expected, got)
		}
	}
	if strings.Count(got, "PROBE OBSERVATIONS") != 0 {
		t.Fatal("multi-candidate text repeated full negative probe detail")
	}
	if strings.Count(got, "PORT & HTTP") != 1 || !strings.Contains(got, "HEAD /: HTTP/1.1 404") || !strings.Contains(got, "X-Powered-By: fixture-http") {
		t.Fatal("shared port profile missing or repeated")
	}
}

func TestMultipleCandidatesCollapseRedirectAlias(t *testing.T) {
	first := mcprecon.Result{Target: mcprecon.Target{Input: "http://lab.test/mcp", Host: "lab.test", Port: 80, Scheme: "http"}, Services: []mcprecon.Service{{Endpoint: "/mcp", Detection: mcprecon.Detection{Status: "confirmed"}, MCP: mcprecon.MCP{Inventories: map[string]mcprecon.Collections{}}}}}
	alias := mcprecon.Result{Target: mcprecon.Target{Input: "http://lab.test/mcp/", Host: "lab.test", Port: 80, Scheme: "http"}, Services: []mcprecon.Service{{Endpoint: "/mcp", Detection: mcprecon.Detection{Status: "confirmed"}, MCP: mcprecon.MCP{Inventories: map[string]mcprecon.Collections{}}}}}
	var out bytes.Buffer
	printResultsStyled(&out, []mcprecon.Result{first, alias}, false, false)
	got := out.String()
	if !strings.Contains(got, "MCP endpoints: 1 | aliases: 1") || !strings.Contains(got, "http://lab.test/mcp/ — MCP alias of http://lab.test/mcp") || strings.Count(got, "IDENTIFICATION") != 1 {
		t.Fatalf("alias was not collapsed:\n%s", got)
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
