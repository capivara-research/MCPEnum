package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/capivara-research/MCPEnum/internal/mcprecon"
)

func printResult(w io.Writer, r mcprecon.Result, showSchemas bool) {
	printResultStyled(w, r, showSchemas, false)
}

func printResultsStyled(w io.Writer, results []mcprecon.Result, showSchemas, color bool) {
	if len(results) == 1 {
		printResultStyled(w, results[0], showSchemas, color)
		return
	}
	confirmed, inconclusive := 0, 0
	canonical := map[string]int{}
	aliases := map[int]int{}
	for i, result := range results {
		if resultConfirmed(result) {
			key := confirmedEndpointKey(result)
			if first, exists := canonical[key]; exists {
				aliases[i] = first
			} else {
				canonical[key] = i
				confirmed++
			}
		} else if len(result.Services) > 0 {
			inconclusive++
		}
	}
	fmt.Fprintf(w, "DISCOVERY SUMMARY  candidates: %d | MCP endpoints: %d | aliases: %d | inconclusive: %d | other: %d\n\n", len(results), confirmed, len(aliases), inconclusive, len(results)-confirmed-len(aliases)-inconclusive)
	for i, result := range results {
		if resultConfirmed(result) {
			if _, alias := aliases[i]; alias {
				continue
			}
			printResultStyled(w, result, showSchemas, color)
		}
	}
	if confirmed < len(results) {
		section(w, "OTHER CANDIDATES", color)
		for i, result := range results {
			if first, alias := aliases[i]; alias {
				fmt.Fprintf(w, "  %s — MCP alias of %s\n", safeLine(result.Target.Input), safeLine(results[first].Target.Input))
				continue
			}
			if resultConfirmed(result) {
				continue
			}
			state := "MCP not confirmed"
			if len(result.Services) > 0 {
				state = "MCP " + statusLabel(result.Services[0].Detection.Status)
			} else if result.ScanStatus == "failed" {
				state = "probe failed"
			}
			outcome := bestProbeOutcome(result.Observations)
			if outcome != "" {
				state += " | " + outcome
			}
			fmt.Fprintf(w, "  %s — %s\n", safeLine(result.Target.Input), state)
		}
		fmt.Fprintln(w, "  Full per-candidate evidence: --format jsonl")
		fmt.Fprintln(w)
	}
}

func confirmedEndpointKey(result mcprecon.Result) string {
	for _, service := range result.Services {
		if service.Detection.Status == "confirmed" {
			return fmt.Sprintf("%s://%s:%d%s", result.Target.Scheme, result.Target.Host, result.Target.Port, service.Endpoint)
		}
	}
	return result.Target.Input
}

func resultConfirmed(result mcprecon.Result) bool {
	for _, service := range result.Services {
		if service.Detection.Status == "confirmed" {
			return true
		}
	}
	return false
}

func bestProbeOutcome(observations []mcprecon.Observation) string {
	var chosen *mcprecon.Observation
	for i := range observations {
		obs := &observations[i]
		if obs.Phase != "discovery" {
			continue
		}
		if chosen == nil || (obs.HTTPStatus > 0 && obs.HTTPStatus != 404 && obs.HTTPStatus != 405 && (chosen.HTTPStatus == 0 || chosen.HTTPStatus == 404 || chosen.HTTPStatus == 405)) {
			chosen = obs
		}
	}
	if chosen == nil {
		return ""
	}
	status := "no HTTP response"
	if chosen.HTTPStatus > 0 {
		status = fmt.Sprintf("HTTP %d", chosen.HTTPStatus)
	}
	if chosen.ErrorCode != "" {
		status += " (" + safeLine(chosen.ErrorCode) + ")"
	}
	if chosen.HTTPServer != "" {
		status += " | server: " + safeLine(chosen.HTTPServer)
	}
	return status
}

func printResultStyled(w io.Writer, r mcprecon.Result, showSchemas, color bool) {
	fmt.Fprintf(w, "TARGET  %s\n", safeLine(r.Target.Input))
	fmt.Fprintf(w, "Result: %s | %d requests | %d ms\n", statusLabel(r.ScanStatus), r.Metrics.Requests, r.Metrics.DurationMS)
	if len(r.Services) == 0 {
		fmt.Fprintln(w, "Summary: MCP not confirmed")
		printUnconfirmed(w, r.Observations, color)
		printWarnings(w, r.Warnings, color)
		fmt.Fprintln(w)
		return
	}
	printSummary(w, r.Services)
	for _, s := range r.Services {
		printService(w, s, showSchemas, color)
	}
	printWarnings(w, r.Warnings, color)
	fmt.Fprintln(w)
}

func printUnconfirmed(w io.Writer, observations []mcprecon.Observation, color bool) {
	if len(observations) == 0 {
		return
	}
	section(w, "PROBE OBSERVATIONS", color)
	for _, obs := range observations {
		if obs.Phase != "discovery" {
			continue
		}
		outcome := "no HTTP response"
		if obs.HTTPStatus > 0 {
			outcome = fmt.Sprintf("HTTP %d", obs.HTTPStatus)
		}
		if obs.ErrorCode != "" {
			outcome += " (" + safeLine(obs.ErrorCode) + ")"
		} else if obs.RPCCode != 0 {
			outcome += fmt.Sprintf(" (JSON-RPC %d)", obs.RPCCode)
		}
		if obs.HTTPServer != "" {
			outcome += " | server: " + safeLine(obs.HTTPServer)
		}
		if obs.ContentType != "" {
			outcome += " | content-type: " + safeLine(obs.ContentType)
		}
		fmt.Fprintf(w, "  %s: %s\n", safeLine(obs.Method), outcome)
	}
	fmt.Fprintln(w, "  Next: check the scheme and port; try authorized alternate paths with --target or --path.")
}

func printSummary(w io.Writer, services []mcprecon.Service) {
	if len(services) == 0 {
		return
	}
	s := services[0]
	if s.Detection.Status != "confirmed" {
		fmt.Fprintf(w, "Summary: MCP %s; confirmation pending\n", statusLabel(s.Detection.Status))
		return
	}
	if c, ok := s.MCP.Inventories["anonymous"]; ok {
		if c.Tools.Status != "complete" && c.Tools.Status != "empty" && c.Tools.Status != "partial" {
			fmt.Fprintf(w, "Summary: MCP confirmed | anonymous tool inventory: %s\n", statusLabel(c.Tools.Status))
			return
		}
		review := 0
		for _, tool := range c.Tools.Items {
			if len(toolHints(stringValue(tool["name"]), s.Findings, c.Tools.EvidenceIDs)) > 0 {
				review++
			}
		}
		fmt.Fprintf(w, "Summary: MCP confirmed | anonymously listed tools: %d (%s) | review leads: %d\n", c.Tools.Count, statusLabel(c.Tools.Status), review)
		return
	}
	fmt.Fprintln(w, "Summary: MCP confirmed | anonymous inventory unavailable")
}

func printService(w io.Writer, s mcprecon.Service, showSchemas, color bool) {
	section(w, "IDENTIFICATION", color)
	fmt.Fprintf(w, "  MCP: %s | confidence: %s\n", statusLabel(s.Detection.Status), statusLabel(s.Detection.Confidence))
	fmt.Fprintf(w, "  Endpoint: %s\n", safeLine(s.Endpoint))
	if s.MCP.ServerName != "" {
		nameVersion := strings.TrimSpace(safeLine(s.MCP.ServerName) + " " + safeLine(s.MCP.ServerVersion))
		fmt.Fprintf(w, "  Server: %s (self-reported)\n", nameVersion)
	}
	fmt.Fprintf(w, "  Transport: %s | era: %s\n", transportLabel(s.MCP.Transport), statusLabel(s.MCP.Era))
	version := s.MCP.ProtocolVersion
	if version == "" {
		version = "unknown (not reported by server)"
	}
	fmt.Fprintf(w, "  MCP version: %s\n", safeLine(version))
	fmt.Fprintf(w, "  Session: %s\n", sessionLabel(s.MCP.Session))
	fmt.Fprintf(w, "  Advertised capabilities: %s\n", mapKeys(s.MCP.Capabilities))

	section(w, "ACCESS", color)
	fmt.Fprintf(w, "  Anonymous listing: %s\n", statusLabel(s.Authentication.Anonymous))
	fmt.Fprintf(w, "  Credentialed listing: %s\n", statusLabel(s.Authentication.Credentialed))
	fmt.Fprintln(w, "  Tool execution: not tested")
	if c, ok := s.MCP.Inventories["anonymous"]; ok && (c.Tools.Status == "complete" || c.Tools.Status == "partial") && c.Tools.Count > 0 {
		fmt.Fprintf(w, "  Tools listed anonymously: %d\n", c.Tools.Count)
	}
	if s.Authentication.OAuthResource != "" {
		fmt.Fprintf(w, "  OAuth resource: %s\n", safeLine(s.Authentication.OAuthResource))
	}
	if len(s.Authentication.AuthorizationServers) > 0 {
		fmt.Fprintf(w, "  Authorization servers: %s\n", safeLine(strings.Join(s.Authentication.AuthorizationServers, ", ")))
	}
	if len(s.Authentication.Scopes) > 0 {
		fmt.Fprintf(w, "  OAuth scopes: %s\n", safeLine(strings.Join(s.Authentication.Scopes, ", ")))
	}

	for _, identity := range []string{"anonymous", "credentialed"} {
		c, ok := s.MCP.Inventories[identity]
		if !ok {
			continue
		}
		section(w, "INVENTORY "+identityLabel(identity), color)
		printCollection(w, "Tools", c.Tools)
		printCollection(w, "Resources", c.Resources)
		printCollection(w, "Resource templates", c.ResourceTemplates)
		printCollection(w, "Prompts", c.Prompts)

		var review, other []map[string]any
		for _, tool := range c.Tools.Items {
			name, _ := tool["name"].(string)
			if len(toolHints(name, s.Findings, c.Tools.EvidenceIDs)) > 0 {
				review = append(review, tool)
			} else {
				other = append(other, tool)
			}
		}
		if len(review) > 0 {
			subsection(w, fmt.Sprintf("TOOLS WITH REVIEW LEADS (%d)", len(review)), color, "\x1b[1;33m")
			for i, tool := range review {
				printTool(w, i+1, tool, toolHints(stringValue(tool["name"]), s.Findings, c.Tools.EvidenceIDs), showSchemas)
			}
		}
		if len(other) > 0 {
			subsection(w, fmt.Sprintf("OTHER LISTED TOOLS (%d)", len(other)), color, "\x1b[1;34m")
			for i, tool := range other {
				printTool(w, i+1, tool, nil, showSchemas)
			}
		}
		printSimpleItems(w, "Resources", c.Resources.Items, "uri")
		printSimpleItems(w, "Resource templates", c.ResourceTemplates.Items, "uriTemplate")
		printSimpleItems(w, "Prompts", c.Prompts.Items, "name")
	}

	section(w, "OBSERVATIONS", color)
	fmt.Fprintln(w, "  Review leads come from advertised definitions; no tools/call was sent.")
	for _, c := range s.MCP.Inventories {
		if c.Tools.Status == "unsupported" || c.Resources.Status == "unsupported" || c.ResourceTemplates.Status == "unsupported" || c.Prompts.Status == "unsupported" {
			fmt.Fprintln(w, "  Code -32601 means method not found; it does not mean an empty list.")
			break
		}
	}
	if s.Detection.Reason != "" {
		reason := s.Detection.Reason
		if reason == "MCP list confirmed; initialize omitted protocolVersion (nonconformant)" {
			reason = "An MCP list confirmed the service; initialize omitted protocolVersion (nonconformant response)."
		} else if reason == "MCP list confirmed; nonconformant initialize" {
			reason = "An MCP list confirmed the service; initialize used a nonstandard version."
		} else if strings.HasPrefix(reason, "nonconformant initialize; tools/list did not confirm MCP") {
			reason = "Initialize returned a nonstandard version; tools/list did not confirm the service."
		}
		writeWrapped(w, "  Detection: ", "             ", safeLine(reason))
	}
	for _, finding := range s.Findings {
		if strings.HasPrefix(finding.Code, "tool_hint_") || finding.Code == "public_tools" {
			continue
		}
		writeWrapped(w, "  Finding ("+statusLabel(finding.Status)+"): ", "    ", safeLine(finding.Summary))
	}
}

func section(w io.Writer, title string, color bool) {
	fmt.Fprintln(w)
	fmt.Fprintln(w, strings.Repeat("─", 72))
	if color {
		fmt.Fprintf(w, "\x1b[1;33m%s\x1b[0m\n", title)
	} else {
		fmt.Fprintln(w, title)
	}
}

func subsection(w io.Writer, title string, color bool, ansi string) {
	fmt.Fprintln(w)
	if color {
		fmt.Fprintf(w, "  %s%s\x1b[0m\n", ansi, title)
	} else {
		fmt.Fprintf(w, "  %s\n", title)
	}
}

func terminalColorEnabled(mode string, out io.Writer) bool {
	if mode == "always" {
		return true
	}
	if mode == "never" || os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		return false
	}
	f, ok := out.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

func printCollection(w io.Writer, label string, c mcprecon.Collection) {
	if c.Status == "unsupported" || c.Status == "denied" || c.Status == "timeout" || c.Status == "error" || c.Status == "not_tested" {
		fmt.Fprintf(w, "  %-20s %s", label+":", statusLabel(c.Status))
	} else {
		itemWord := "items"
		if c.Count == 1 {
			itemWord = "item"
		}
		fmt.Fprintf(w, "  %-20s %d %s, %s", label+":", c.Count, itemWord, statusLabel(c.Status))
		if c.Pages > 0 {
			pageWord := "pages"
			if c.Pages == 1 {
				pageWord = "page"
			}
			fmt.Fprintf(w, ", %d %s", c.Pages, pageWord)
		}
	}
	if c.ErrorCode != "" {
		fmt.Fprintf(w, " [%s]", safeLine(c.ErrorCode))
	}
	fmt.Fprintln(w)
}

func printTool(w io.Writer, number int, tool map[string]any, hints []string, showSchemas bool) {
	fmt.Fprintf(w, "    %d. %s\n", number, safeLine(stringValue(tool["name"])))
	if len(hints) > 0 {
		labels := make([]string, 0, len(hints))
		for _, hint := range hints {
			labels = append(labels, hintLabel(hint))
		}
		writeWrapped(w, "       Inferred leads: ", "                       ", strings.Join(labels, ", "))
	}
	if description := stringValue(tool["description"]); description != "" {
		writeWrapped(w, "       Description: ", "                    ", safeDescription(description))
	}
	required, optional := toolFields(tool)
	if len(required) > 0 {
		writeWrapped(w, "       Required: ", "                 ", strings.Join(required, ", "))
	}
	if len(optional) > 0 {
		writeWrapped(w, "       Optional: ", "                 ", strings.Join(optional, ", "))
	}
	if showSchemas {
		if schema, ok := tool["inputSchema"]; ok {
			encoded, err := json.MarshalIndent(schema, "         ", "  ")
			if err == nil {
				fmt.Fprintf(w, "       Schema:\n         %s\n", encoded)
			}
		}
	}
}

func printSimpleItems(w io.Writer, label string, items []map[string]any, key string) {
	if len(items) == 0 {
		return
	}
	fmt.Fprintf(w, "\n  LISTED %s (%d)\n", strings.ToUpper(label), len(items))
	for i, item := range items {
		fmt.Fprintf(w, "    %d. %s\n", i+1, safeLine(stringValue(item[key])))
	}
}

func printWarnings(w io.Writer, warnings []string, color bool) {
	if len(warnings) == 0 {
		return
	}
	section(w, "WARNINGS", color)
	for _, warning := range warnings {
		writeWrapped(w, "  - ", "    ", safeLine(warning))
	}
}

func statusLabel(value string) string {
	switch value {
	case "completed", "complete":
		return "complete"
	case "confirmed":
		return "confirmed"
	case "inconclusive":
		return "inconclusive"
	case "high":
		return "high"
	case "medium":
		return "medium"
	case "low":
		return "low"
	case "accepted":
		return "accepted"
	case "required":
		return "required"
	case "rejected":
		return "rejected"
	case "not_tested":
		return "not tested"
	case "empty":
		return "empty"
	case "unsupported":
		return "unsupported"
	case "denied":
		return "denied"
	case "partial":
		return "partial"
	case "timeout":
		return "timed out"
	case "error", "failed":
		return "failed"
	case "modern":
		return "modern"
	case "legacy":
		return "legacy"
	case "unknown", "":
		return "unknown"
	default:
		return safeLine(value)
	}
}

func transportLabel(value string) string {
	switch value {
	case "streamable_http":
		return "Streamable HTTP"
	case "legacy_http_sse":
		return "legacy HTTP+SSE"
	case "stdio":
		return "stdio"
	default:
		return statusLabel(value)
	}
}

func sessionLabel(value string) string {
	switch value {
	case "stateful":
		return "session ID present"
	case "stateless":
		return "stateless"
	default:
		return "unknown"
	}
}

func identityLabel(value string) string {
	if value == "anonymous" {
		return "ANONYMOUS"
	}
	return "CREDENTIALED"
}

func hintLabel(value string) string {
	switch value {
	case "state_change":
		return "state change"
	case "internal_marker":
		return "marked internal"
	case "process_execution":
		return "process execution"
	case "filesystem":
		return "file access"
	case "network":
		return "network access"
	case "environment":
		return "environment variables"
	case "metadata_control":
		return "hidden characters in description"
	case "metadata_instruction":
		return "assistant-directed instructions in description"
	case "terminal_control":
		return "terminal output control"
	case "unsafe_input":
		return "input described as unsafe"
	case "credentials":
		return "secrets/credentials"
	case "database":
		return "database access"
	default:
		return safeLine(value)
	}
}

func mapKeys(m map[string]any) string {
	if len(m) == 0 {
		return "none"
	}
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, safeLine(key))
	}
	sort.Strings(keys)
	return strings.Join(keys, ", ")
}

func toolHints(name string, findings []mcprecon.Finding, collectionEvidence []string) []string {
	seen := map[string]bool{}
	evidence := map[string]bool{}
	for _, id := range collectionEvidence {
		evidence[id] = true
	}
	for _, finding := range findings {
		if !strings.HasPrefix(finding.Code, "tool_hint_") || !strings.HasPrefix(finding.SourcePath, "tools["+name+"].") {
			continue
		}
		for _, id := range finding.EvidenceIDs {
			if evidence[id] {
				seen[finding.Category] = true
				break
			}
		}
	}
	var out []string
	for category := range seen {
		out = append(out, category)
	}
	sort.Strings(out)
	return out
}

func toolFields(tool map[string]any) (requiredFields, optionalFields []string) {
	schema, _ := tool["inputSchema"].(map[string]any)
	properties, _ := schema["properties"].(map[string]any)
	required := map[string]bool{}
	if names, ok := schema["required"].([]any); ok {
		for _, value := range names {
			if name, ok := value.(string); ok {
				required[name] = true
			}
		}
	}
	var names []string
	for name := range properties {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		field, _ := properties[name].(map[string]any)
		typ, _ := field["type"].(string)
		if typ == "" {
			typ = "any"
		}
		label := safeLine(name) + " (" + safeLine(typ) + ")"
		if required[name] {
			requiredFields = append(requiredFields, label)
		} else {
			optionalFields = append(optionalFields, label)
		}
	}
	return requiredFields, optionalFields
}

func stringValue(value any) string {
	s, _ := value.(string)
	return s
}

func writeWrapped(w io.Writer, firstIndent, nextIndent, value string) {
	words := strings.Fields(value)
	if len(words) == 0 {
		fmt.Fprintln(w, strings.TrimRight(firstIndent, " "))
		return
	}
	line, width := firstIndent, utf8.RuneCountInString(firstIndent)
	hasWord := false
	for _, word := range words {
		length := utf8.RuneCountInString(word)
		if hasWord && width+1+length > 100 {
			fmt.Fprintln(w, line)
			line, width = nextIndent, utf8.RuneCountInString(nextIndent)
			hasWord = false
		}
		if hasWord {
			line += " "
			width++
		}
		line += word
		width += length
		hasWord = true
	}
	fmt.Fprintln(w, line)
}

func safeLine(s string) string { return safeLineLimit(s, 240) }

func safeDescription(s string) string { return safeLineLimit(s, 1024) }

func safeLineLimit(s string, limit int) string {
	var b strings.Builder
	for _, r := range s {
		if r == '\x1b' {
			b.WriteString("\\x1b")
		} else if r == '\u200b' || r == '\u200c' || r == '\u200d' || r == '\ufeff' || r >= '\u202a' && r <= '\u202e' || r >= '\u2066' && r <= '\u2069' {
			b.WriteString(fmt.Sprintf("\\u%04x", r))
		} else if r < 32 || r == 127 {
			b.WriteRune(' ')
		} else {
			b.WriteRune(r)
		}
		if b.Len() >= limit {
			b.WriteString("…")
			break
		}
	}
	return b.String()
}
