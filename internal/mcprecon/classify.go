package mcprecon

import (
	"fmt"
	"strings"
)

// toolHints are leads for manual review. They are never proof of execution.
var toolHints = []struct {
	category string
	terms    []string
}{
	{"state_change", []string{"add_", "create_", "delete_", "update_", "write_", "remove_", "register_", "insert", "modify"}},
	{"internal_marker", []string{"internal", "backend-only", "do not list", "do not advertise", "restricted"}},
	{"process_execution", []string{"execute", "shell", "command", "run_code", "subprocess"}},
	{"filesystem", []string{"path", "directory", "filesystem", "read_file", "write_file"}},
	{"network", []string{"url", "http", "browser", "webhook"}},
	{"environment", []string{"environment variable", "environment_variable", "process.env"}},
	{"credentials", []string{"secret", "token", "credential", "password", "api_key"}},
	{"database", []string{"sql", "database", "table"}},
	{"unsafe_input", []string{"unsafe concatenation", "unvalidated input", "unsanitized input"}},
}

func classifyTools(c Collection) []Finding {
	var findings []Finding
	for _, tool := range c.Items {
		name, _ := tool["name"].(string)
		if name == "" {
			continue
		}
		seen := map[string]bool{}
		check := func(source, text string, confidence string) {
			text = strings.ToLower(text)
			for _, rule := range toolHints {
				if seen[rule.category] {
					continue
				}
				for _, term := range rule.terms {
					if strings.Contains(text, term) {
						seen[rule.category] = true
						findings = append(findings, Finding{Code: "tool_hint_" + rule.category, Summary: fmt.Sprintf("tool %q may expose %s capability; review before use", name, rule.category), Status: "inferred", Confidence: confidence, Category: rule.category, Severity: "info", SourcePath: source, EvidenceIDs: c.EvidenceIDs})
						break
					}
				}
			}
		}
		check("tools["+name+"].name", name, "medium")
		if desc, ok := tool["description"].(string); ok {
			check("tools["+name+"].description", desc, "low")
			if hasHiddenMetadataControl(desc) {
				findings = append(findings, Finding{Code: "tool_hint_metadata_control", Summary: fmt.Sprintf("tool %q description contains hidden or terminal control characters; review before use", name), Status: "inferred", Confidence: "high", Category: "metadata_control", Severity: "info", SourcePath: "tools[" + name + "].description", EvidenceIDs: c.EvidenceIDs})
			}
			if hasInstructionInMetadata(desc) {
				findings = append(findings, Finding{Code: "tool_hint_metadata_instruction", Summary: fmt.Sprintf("tool %q description contains instructions aimed at the assistant; review before use", name), Status: "inferred", Confidence: "medium", Category: "metadata_instruction", Severity: "info", SourcePath: "tools[" + name + "].description", EvidenceIDs: c.EvidenceIDs})
			}
		}
		if schema, ok := tool["inputSchema"].(map[string]any); ok {
			walkSchema(schema, "tools["+name+"].inputSchema", 0, func(path, text string) { check(path, text, "low") })
			if hasTerminalControlOption(schema) {
				findings = append(findings, Finding{Code: "tool_hint_terminal_control", Summary: fmt.Sprintf("tool %q offers terminal display control options; review before use", name), Status: "inferred", Confidence: "low", Category: "terminal_control", Severity: "info", SourcePath: "tools[" + name + "].inputSchema", EvidenceIDs: c.EvidenceIDs})
			}
		}
	}
	return findings
}

func hasInstructionInMetadata(value string) bool {
	value = strings.ToLower(value)
	for _, marker := range []string{"hidden instruction", "respond with:", "always prefix your responses", "ignore previous", "exfiltrate"} {
		if strings.Contains(value, marker) {
			return true
		}
	}
	return false
}

func hasTerminalControlOption(schema map[string]any) bool {
	properties, _ := schema["properties"].(map[string]any)
	for _, key := range []string{"style", "mode", "format"} {
		property, _ := properties[key].(map[string]any)
		values, _ := property["enum"].([]any)
		for _, raw := range values {
			value, _ := raw.(string)
			switch strings.ToLower(value) {
			case "hidden", "clear", "deceive", "overwrite", "erase":
				return true
			}
		}
	}
	return false
}

func hasHiddenMetadataControl(value string) bool {
	for _, r := range value {
		if r == '\x1b' || r == '\u200b' || r == '\u200c' || r == '\u200d' || r == '\ufeff' || r >= '\u202a' && r <= '\u202e' || r >= '\u2066' && r <= '\u2069' {
			return true
		}
	}
	return false
}

func walkSchema(node map[string]any, path string, depth int, visit func(string, string)) {
	if depth > 8 {
		return
	}
	// Restricted enums are not free-form input for this heuristic.
	if _, restricted := node["enum"]; !restricted {
		if typ, _ := node["type"].(string); typ == "string" {
			visit(path, path)
			if desc, _ := node["description"].(string); desc != "" {
				visit(path, desc)
			}
		}
	}
	for _, key := range []string{"properties", "$defs", "definitions"} {
		if children, ok := node[key].(map[string]any); ok {
			for name, raw := range children {
				if child, ok := raw.(map[string]any); ok {
					walkSchema(child, path+"."+key+"."+name, depth+1, visit)
				}
			}
		}
	}
	if child, ok := node["items"].(map[string]any); ok {
		walkSchema(child, path+".items", depth+1, visit)
	}
	for _, key := range []string{"anyOf", "oneOf", "allOf"} {
		if children, ok := node[key].([]any); ok {
			for i, raw := range children {
				if child, ok := raw.(map[string]any); ok {
					walkSchema(child, fmt.Sprintf("%s.%s[%d]", path, key, i), depth+1, visit)
				}
			}
		}
	}
}
