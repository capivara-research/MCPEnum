package mcprecon

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

var standardPaths = []string{"/mcp", "/", "/sse", "/api/mcp", "/api/v1/mcp", "/mcp/v1", "/v1/mcp", "/messages"}
var broadPaths = []string{"/mcp", "/", "/sse", "/messages", "/api/mcp", "/api/v1/mcp", "/mcp/v1", "/v1/mcp", "/rpc", "/jsonrpc", "/mcp/sse", "/mcp/message", "/mcp/messages", "/stream", "/api", "/server"}
var extensivePaths = []string{
	"/mcp", "/", "/sse", "/api/mcp", "/mcp/v1", "/v1/mcp", "/messages",
	"/mcp/", "/api/mcp/", "/api/v1/mcp", "/api/v2/mcp", "/server/mcp", "/mcp/server",
	"/rpc", "/jsonrpc", "/mcp/sse", "/api/sse", "/api/v1/sse", "/mcp/message", "/mcp/messages",
	"/message", "/stream", "/api/stream", "/api", "/server", "/api/v1", "/mcp-server",
}

func StandardPaths() []string  { return append([]string(nil), standardPaths...) }
func BroadPaths() []string     { return append([]string(nil), broadPaths...) }
func ExtensivePaths() []string { return append([]string(nil), extensivePaths...) }

func Defaults() Config {
	return Config{Ports: []int{443, 3000, 8000, 8080}, Paths: BroadPaths(), Timeout: 5000, Budget: 30000, Workers: 16, MaxPages: 32, MaxItems: 5000, MaxBody: 2 << 20, MaxHosts: 16, UserAgent: "MCPEnum/0.1.0", HTTPProbe: "basic"}
}

func Scan(ctx context.Context, cfg Config) ([]Result, error) {
	if len(cfg.Paths) > 128 {
		return nil, errors.New("too many candidate paths (maximum 128)")
	}
	urls, err := expandTargets(cfg)
	if err != nil {
		return nil, err
	}
	if len(urls) == 0 {
		return nil, errors.New("no targets supplied")
	}
	if cfg.Workers < 1 || cfg.Workers > 256 || cfg.Timeout < 100 || cfg.Budget < cfg.Timeout || cfg.MaxPages < 1 || cfg.MaxItems < 1 || cfg.MaxBody < 1024 || cfg.Rate < 0 || cfg.Rate > 10000 || len(cfg.UserAgent) > 128 || strings.ContainsAny(cfg.UserAgent, "\r\n") || (cfg.HTTPProbe != "off" && cfg.HTTPProbe != "basic" && cfg.HTTPProbe != "extended") {
		return nil, errors.New("invalid scan limits")
	}
	if cfg.Rate > 0 {
		ticker := time.NewTicker(time.Second / time.Duration(cfg.Rate))
		defer ticker.Stop()
		cfg.gate = ticker.C
	}
	results := make([]Result, len(urls))
	jobs := make(chan int)
	var wg sync.WaitGroup
	var completed atomic.Int64
	if cfg.Progress != nil {
		total := len(urls)
		if cfg.HTTPProbe != "off" {
			origins := map[string]bool{}
			for _, raw := range urls {
				u, _ := url.Parse(raw)
				origins[u.Scheme+"://"+u.Host] = true
			}
			total += len(origins)
		}
		cfg.Progress(ProgressEvent{Phase: "total", Done: 0, Total: total})
		cfg.Progress(ProgressEvent{Phase: "mcp", Done: 0, Total: len(urls)})
	}
	for i := 0; i < cfg.Workers && i < len(urls); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				if cfg.Progress != nil {
					cfg.Progress(ProgressEvent{Phase: "start", Target: urls[idx], Status: "starting"})
				}
				results[idx] = scanURL(ctx, urls[idx], cfg)
				if cfg.Progress != nil {
					cfg.Progress(ProgressEvent{Phase: "mcp", Done: int(completed.Add(1)), Total: len(urls), Target: urls[idx], Status: results[idx].ScanStatus})
				}
			}
		}()
	}
	for i := range urls {
		select {
		case jobs <- i:
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			return results, ctx.Err()
		}
	}
	close(jobs)
	wg.Wait()
	if cfg.HTTPProbe != "off" {
		attachPortProfiles(ctx, results, cfg)
	}
	return results, nil
}

func expandTargets(cfg Config) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	for _, raw := range cfg.URLs {
		u, e := url.Parse(raw)
		if e != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.Fragment != "" || u.RawQuery != "" {
			return nil, fmt.Errorf("invalid --url: %q", raw)
		}
		if u.Path == "" {
			u.Path = "/mcp"
		}
		add(u.String())
	}
	for _, target := range cfg.Targets {
		if strings.ContainsAny(target, "?#@") {
			return nil, fmt.Errorf("invalid target: %q", target)
		}
		hosts := []string{target}
		if strings.Contains(target, "/") {
			if !cfg.AllowCIDR {
				return nil, errors.New("CIDR requires --allow-cidr")
			}
			prefix, e := netip.ParsePrefix(target)
			if e != nil {
				return nil, fmt.Errorf("invalid CIDR: %q", target)
			}
			hosts = nil
			for ip := prefix.Masked().Addr(); ip.IsValid() && prefix.Contains(ip); ip = ip.Next() {
				if len(hosts) >= cfg.MaxHosts {
					return nil, errors.New("CIDR exceeds --max-hosts")
				}
				hosts = append(hosts, ip.String())
			}
		}
		for _, hostport := range hosts {
			host := hostport
			ports := cfg.Ports
			if h, p, e := net.SplitHostPort(hostport); e == nil {
				host = h
				var n int
				_, e = fmt.Sscanf(p, "%d", &n)
				if e != nil || n < 1 || n > 65535 {
					return nil, fmt.Errorf("invalid port in %q", target)
				}
				ports = []int{n}
			}
			if host == "" {
				return nil, fmt.Errorf("empty host")
			}
			for _, port := range ports {
				if port < 1 || port > 65535 {
					return nil, fmt.Errorf("invalid port: %d", port)
				}
				scheme := "http"
				if port == 443 {
					scheme = "https"
				}
				for _, path := range cfg.Paths {
					if !safePath(path) {
						return nil, fmt.Errorf("invalid path: %q", path)
					}
					add((&url.URL{Scheme: scheme, Host: net.JoinHostPort(host, fmt.Sprint(port)), Path: path}).String())
				}
			}
		}
	}
	if len(out) > cfg.MaxHosts*len(cfg.Ports)*len(cfg.Paths)+len(cfg.URLs) {
		return nil, errors.New("target expansion exceeds limit")
	}
	return out, nil
}

func legacySSECandidate(path string) bool {
	return path == "/mcp" || strings.HasSuffix(path, "/sse")
}

func safePath(p string) bool {
	return len(p) <= 256 && strings.HasPrefix(p, "/") && !strings.HasPrefix(p, "//") && !strings.ContainsAny(p, "\r\n\\?#") && !strings.Contains(p, "..")
}

func scanURL(ctx context.Context, raw string, cfg Config) Result {
	start := time.Now()
	u, _ := url.Parse(raw)
	port := 80
	if u.Scheme == "https" {
		port = 443
	}
	if p := u.Port(); p != "" {
		fmt.Sscanf(p, "%d", &port)
	}
	r := Result{SchemaVersion: "2.0", Scanner: "mcpenum", Target: Target{Input: raw, Host: u.Hostname(), Port: port, Scheme: u.Scheme}, ScanStatus: "completed", Services: []Service{}, Observations: []Observation{}, Metrics: Metrics{}}
	bctx, cancel := context.WithTimeout(ctx, time.Duration(cfg.Budget)*time.Millisecond)
	defer cancel()
	anon, ac := scanContext(bctx, raw, cfg, "", &r)
	if anon != nil {
		r.Services = append(r.Services, *anon)
	}
	if cfg.Token != "" && bctx.Err() == nil {
		cred, cc := scanContext(bctx, raw, cfg, cfg.Token, &r)
		if cred != nil {
			if len(r.Services) == 0 {
				r.Services = append(r.Services, *cred)
			} else {
				mergeService(&r.Services[0], cred)
			}
		}
		if len(r.Services) > 0 {
			r.Services[0].Authentication.Credentialed = cc
		}
	}
	if len(r.Services) > 0 {
		r.Services[0].Authentication.Anonymous = ac
	}
	if bctx.Err() != nil {
		r.ScanStatus = "partial"
		r.Warnings = append(r.Warnings, "target budget or context deadline reached")
	}
	for _, s := range r.Services {
		if s.Detection.Status == "inconclusive" {
			r.ScanStatus = "partial"
		}
		for _, coll := range s.MCP.Inventories {
			for _, state := range []string{coll.Tools.Status, coll.Resources.Status, coll.ResourceTemplates.Status, coll.Prompts.Status} {
				if state == "partial" || state == "error" || state == "timeout" {
					r.ScanStatus = "partial"
				}
			}
		}
	}
	if len(r.Observations) > 0 {
		allTransport := true
		for _, obs := range r.Observations {
			if obs.HTTPStatus != 0 {
				allTransport = false
				break
			}
		}
		if allTransport {
			r.ScanStatus = "failed"
			r.Warnings = append(r.Warnings, "no HTTP response; inspect DNS, TCP, or TLS errors")
		}
	}
	r.Metrics.DurationMS = time.Since(start).Milliseconds()
	return r
}

func mergeService(dst *Service, src *Service) {
	if dst.Detection.Status != "confirmed" && src.Detection.Status == "confirmed" {
		dst.Detection = src.Detection
		dst.MCP.Transport = src.MCP.Transport
		dst.MCP.Era = src.MCP.Era
		dst.MCP.Session = src.MCP.Session
		dst.MCP.ProtocolVersion = src.MCP.ProtocolVersion
		dst.MCP.ServerName = src.MCP.ServerName
		dst.MCP.ServerVersion = src.MCP.ServerVersion
		dst.MCP.Capabilities = src.MCP.Capabilities
	}
	if dst.MCP.Inventories == nil {
		dst.MCP.Inventories = map[string]Collections{}
	}
	for k, v := range src.MCP.Inventories {
		dst.MCP.Inventories[k] = v
	}
	dst.Findings = append(dst.Findings, src.Findings...)
}

func sessionState(id string) string {
	if id != "" {
		return "stateful"
	}
	return "stateless"
}

func scanContext(ctx context.Context, raw string, cfg Config, token string, r *Result) (*Service, string) {
	c, err := newClient(raw, cfg, token, r)
	if err != nil {
		r.Warnings = append(r.Warnings, "invalid endpoint")
		return nil, "error"
	}
	defer c.close()
	identity := "anonymous"
	if token != "" {
		identity = "credentialed"
	}
	svc := &Service{Kind: "mcp", Endpoint: c.endpoint.Path, Detection: Detection{Status: "inconclusive", EvidenceIDs: []string{}}, Authentication: Authentication{Anonymous: "not_tested", Credentialed: "not_tested"}, MCP: MCP{Transport: "unknown", Era: "unknown", Inventories: map[string]Collections{}}}
	var seedTools *Collection
	disc := c.request(ctx, "server/discover", nil, "discovery")
	if disc.ResolvedPath != "" && !disc.ResolvedHasQuery {
		svc.Endpoint = disc.ResolvedPath
	}
	discID := lastID(r)
	if disc.HTTPStatus == 401 || disc.HTTPStatus == 403 {
		svc.Detection.Reason = "HTTP authentication challenge; MCP unconfirmed"
		svc.Detection.EvidenceIDs = []string{discID}
		if token == "" {
			svc.Authentication.Anonymous = "required"
		} else {
			svc.Authentication.Credentialed = "rejected"
		}
		readOAuthMetadata(ctx, c, disc.Headers, svc, r)
		return svc, authState(svc, token)
	}
	if disc.Err == nil && disc.RPC.Error == nil {
		var data struct {
			SupportedVersions []string                   `json:"supportedVersions"`
			Capabilities      map[string]any             `json:"capabilities"`
			Meta              map[string]json.RawMessage `json:"_meta"`
		}
		if json.Unmarshal(disc.RPC.Result, &data) == nil && has(data.SupportedVersions, modernVersion) && data.Capabilities != nil {
			c.era = "modern"
			c.version = modernVersion
			svc.Detection = Detection{Status: "confirmed", Confidence: "high", EvidenceIDs: []string{discID}}
			svc.MCP.Transport = "streamable_http"
			svc.MCP.Era = "modern"
			svc.MCP.Session = "stateless"
			svc.MCP.ProtocolVersion = modernVersion
			svc.MCP.Capabilities = data.Capabilities
			var info struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			}
			_ = json.Unmarshal(data.Meta["io.modelcontextprotocol/serverInfo"], &info)
			svc.MCP.ServerName = info.Name
			svc.MCP.ServerVersion = info.Version
		}
	}
	if svc.Detection.Status != "confirmed" {
		// A failed modern probe is not evidence of MCP. Try one legacy handshake.
		init := c.request(ctx, "initialize", map[string]any{"protocolVersion": legacyVersion, "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "MCPEnum", "version": "0.1.0"}}, "discovery")
		if init.ResolvedPath != "" && !init.ResolvedHasQuery {
			svc.Endpoint = init.ResolvedPath
		}
		initID := lastID(r)
		if init.RPC.Error != nil && init.RPC.Error.Code == -32022 {
			if offered := legacyOffer(init.RPC.Error.Data); offered != "" && offered != legacyVersion {
				init = c.request(ctx, "initialize", map[string]any{"protocolVersion": offered, "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "MCPEnum", "version": "0.1.0"}}, "discovery")
				if init.ResolvedPath != "" && !init.ResolvedHasQuery {
					svc.Endpoint = init.ResolvedPath
				}
				initID = lastID(r)
			}
		}
		if init.HTTPStatus == 401 || init.HTTPStatus == 403 {
			svc.Detection.Reason = "HTTP authentication challenge; MCP unconfirmed"
			svc.Detection.EvidenceIDs = []string{initID}
			if token == "" {
				svc.Authentication.Anonymous = "required"
			} else {
				svc.Authentication.Credentialed = "rejected"
			}
			readOAuthMetadata(ctx, c, init.Headers, svc, r)
			return svc, authState(svc, token)
		}
		if init.Err == nil && init.RPC.Error == nil && acceptInitialize(init.RPC.Result, svc) {
			c.era = "legacy"
			c.version = svc.MCP.ProtocolVersion
			c.session = init.Headers.Get("Mcp-Session-Id")
			svc.MCP.Session = sessionState(c.session)
			svc.MCP.Transport = "streamable_http"
			svc.Detection = Detection{Status: "confirmed", Confidence: "high", EvidenceIDs: []string{initID}}
			_ = c.notify(ctx, "notifications/initialized")
		} else if init.Err == nil && init.RPC.Error == nil && nonconformantLegacyInfo(init.RPC.Result, svc) {
			// Nonstandard servers may omit or invent protocolVersion. A valid
			// initialize shape is a lead; only a valid MCP list confirms it.
			c.session = init.Headers.Get("Mcp-Session-Id")
			c.version = svc.MCP.ProtocolVersion
			probe := c.request(ctx, "tools/list", nil, "inventory")
			probeID := lastID(r)
			listed := listWithInitial(ctx, c, "tools/list", "tools", &probe, probeID)
			if listed.Status == "complete" || listed.Status == "empty" || listed.Status == "partial" {
				seedTools = &listed
				svc.MCP.Transport = "streamable_http"
				svc.MCP.Era = "legacy"
				svc.MCP.Session = sessionState(c.session)
				reason := "MCP list confirmed; nonconformant initialize"
				if svc.MCP.ProtocolVersion == "" {
					reason = "MCP list confirmed; initialize omitted protocolVersion (nonconformant)"
				}
				svc.Detection = Detection{Status: "confirmed", Confidence: "high", EvidenceIDs: []string{initID, probeID}, Reason: reason}
			} else {
				svc.Detection = Detection{Status: "inconclusive", Confidence: "low", EvidenceIDs: []string{initID, probeID}, Reason: "nonconformant initialize; tools/list did not confirm MCP (" + listed.Status + ")"}
			}
		} else if legacySSECandidate(c.endpoint.Path) && ctx.Err() == nil {
			if e := c.startLegacySSE(ctx); e == nil {
				init := c.request(ctx, "initialize", map[string]any{"protocolVersion": legacyVersion, "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "MCPEnum", "version": "0.1.0"}}, "discovery")
				if init.Err == nil && init.RPC.Error == nil && acceptInitialize(init.RPC.Result, svc) {
					c.era = "legacy"
					c.version = svc.MCP.ProtocolVersion
					svc.MCP.Transport = "legacy_http_sse"
					svc.MCP.Session = legacySSESessionState(c.legacy.postURL)
					svc.Detection = Detection{Status: "confirmed", Confidence: "high", EvidenceIDs: []string{lastID(r)}}
					_ = c.notify(ctx, "notifications/initialized")
				}
			}
		}
		if svc.Detection.Status != "confirmed" && (disc.HTTPStatus == 404 || disc.HTTPStatus == 405) && (init.HTTPStatus == 404 || init.HTTPStatus == 405) {
			if !legacySSECandidate(c.endpoint.Path) {
				return nil, "unknown"
			}
			// For an SSE candidate, the GET is the last transport attempt.
			// A 404/405 there closes the case just as it does for the POSTs.
			if n := len(r.Observations); n > 0 {
				last := r.Observations[n-1]
				if last.Method == "GET" && (last.HTTPStatus == 404 || last.HTTPStatus == 405) {
					return nil, "unknown"
				}
			}
		}
	}
	if svc.Detection.Status != "confirmed" {
		if svc.Detection.Status == "inconclusive" && svc.Detection.Reason != "" {
			return svc, "unknown"
		}
		if disc.Err != nil {
			svc.Detection.Reason = "transport or invalid RPC response"
			svc.Detection.EvidenceIDs = []string{discID}
			r.Warnings = append(r.Warnings, "probe "+c.endpoint.Path+": "+safeError(disc.Err))
			return svc, "error"
		}
		return nil, "unknown"
	}
	if token == "" {
		svc.Authentication.Anonymous = "accepted"
	} else {
		svc.Authentication.Credentialed = "accepted"
	}
	collections := enumerate(ctx, c, seedTools)
	svc.MCP.Inventories[identity] = collections
	svc.Findings = append(svc.Findings, classifyTools(collections.Tools)...)
	if token == "" {
		svc.Findings = append(svc.Findings, publicFindings(collections)...)
	}
	return svc, "accepted"
}

func acceptInitialize(raw json.RawMessage, svc *Service) bool {
	var data struct {
		ProtocolVersion string         `json:"protocolVersion"`
		Capabilities    map[string]any `json:"capabilities"`
		ServerInfo      struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"serverInfo"`
	}
	if json.Unmarshal(raw, &data) != nil || data.ProtocolVersion == "" || data.Capabilities == nil || data.ServerInfo.Name == "" {
		return false
	}
	if !has([]string{"2024-11-05", "2025-03-26", "2025-06-18", legacyVersion}, data.ProtocolVersion) {
		return false
	}
	svc.MCP.Era = "legacy"
	svc.MCP.ProtocolVersion = data.ProtocolVersion
	svc.MCP.Capabilities = data.Capabilities
	svc.MCP.ServerName = data.ServerInfo.Name
	svc.MCP.ServerVersion = data.ServerInfo.Version
	return true
}

func nonconformantLegacyInfo(raw json.RawMessage, svc *Service) bool {
	var data struct {
		ProtocolVersion string         `json:"protocolVersion"`
		Capabilities    map[string]any `json:"capabilities"`
		ServerInfo      struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"serverInfo"`
	}
	if json.Unmarshal(raw, &data) != nil || data.ServerInfo.Name == "" || data.Capabilities == nil {
		return false
	}
	if has([]string{"2024-11-05", "2025-03-26", "2025-06-18", legacyVersion}, data.ProtocolVersion) {
		return false
	}
	if _, ok := data.Capabilities["tools"]; !ok {
		return false
	}
	svc.MCP.ServerName = data.ServerInfo.Name
	svc.MCP.ServerVersion = data.ServerInfo.Version
	svc.MCP.ProtocolVersion = data.ProtocolVersion
	svc.MCP.Capabilities = data.Capabilities
	return true
}

func has(items []string, x string) bool {
	for _, item := range items {
		if item == x {
			return true
		}
	}
	return false
}

func legacyOffer(raw json.RawMessage) string {
	var data struct {
		Supported []string `json:"supported"`
	}
	if json.Unmarshal(raw, &data) != nil {
		return ""
	}
	for _, v := range []string{legacyVersion, "2025-06-18", "2025-03-26", "2024-11-05"} {
		if has(data.Supported, v) {
			return v
		}
	}
	return ""
}
func lastID(r *Result) string {
	if len(r.Observations) == 0 {
		return ""
	}
	return r.Observations[len(r.Observations)-1].ID
}
func authState(s *Service, token string) string {
	if token == "" {
		return s.Authentication.Anonymous
	}
	return s.Authentication.Credentialed
}

func enumerate(ctx context.Context, c *client, seedTools *Collection) Collections {
	var tools Collection
	if seedTools != nil {
		tools = *seedTools
	} else {
		tools = list(ctx, c, "tools/list", "tools")
	}
	return Collections{
		Tools:             tools,
		Resources:         list(ctx, c, "resources/list", "resources"),
		ResourceTemplates: list(ctx, c, "resources/templates/list", "resourceTemplates"),
		Prompts:           list(ctx, c, "prompts/list", "prompts"),
	}
}

func list(ctx context.Context, c *client, method, key string) Collection {
	return listWithInitial(ctx, c, method, key, nil, "")
}

func listWithInitial(ctx context.Context, c *client, method, key string, initial *wireReply, initialID string) Collection {
	out := Collection{Status: "not_tested", Items: []map[string]any{}}
	if ctx.Err() != nil {
		out.Status = "timeout"
		out.ErrorCode = "budget"
		return out
	}
	seenCursor := map[string]bool{}
	seenItem := map[string]bool{}
	cursor := ""
	for page := 0; page < c.config.MaxPages; page++ {
		params := map[string]any{}
		if cursor != "" {
			params["cursor"] = cursor
		}
		var reply wireReply
		evidenceID := initialID
		if page == 0 && initial != nil {
			reply = *initial
		} else {
			reply = c.request(ctx, method, params, "inventory")
			evidenceID = lastID(c.result)
		}
		out.EvidenceIDs = append(out.EvidenceIDs, evidenceID)
		if reply.HTTPStatus == 401 || reply.HTTPStatus == 403 {
			out.Status = "denied"
			out.ErrorCode = fmt.Sprintf("http_%d", reply.HTTPStatus)
			return out
		}
		if reply.Err != nil {
			out.Status = "error"
			if ctx.Err() != nil {
				out.Status = "timeout"
			}
			out.ErrorCode = safeError(reply.Err)
			return out
		}
		if reply.RPC.Error != nil {
			if reply.RPC.Error.Code == -32601 {
				out.Status = "unsupported"
			} else {
				out.Status = "error"
			}
			out.ErrorCode = fmt.Sprint(reply.RPC.Error.Code)
			out.ErrorMessage = reply.RPC.Error.Message
			return out
		}
		var data map[string]json.RawMessage
		if json.Unmarshal(reply.RPC.Result, &data) != nil {
			out.Status = "error"
			out.ErrorCode = "invalid_result"
			return out
		}
		if raw, ok := data["resultType"]; ok && string(raw) != `"complete"` {
			out.Status = "error"
			out.ErrorCode = "non_complete_result"
			return out
		}
		var items []map[string]any
		if _, ok := data[key]; !ok || json.Unmarshal(data[key], &items) != nil || items == nil {
			out.Status = "error"
			out.ErrorCode = "missing_collection"
			return out
		}
		out.Pages++
		truncated := false
		for _, item := range items {
			if !validItem(key, item) {
				if out.Count > 0 {
					out.Status = "partial"
				} else {
					out.Status = "error"
				}
				out.ErrorCode = "invalid_item"
				return out
			}
			// De-duplicate by stable JSON while preserving the first page's order.
			b, _ := json.Marshal(item)
			k := string(b)
			if !seenItem[k] {
				if out.Count >= c.config.MaxItems {
					truncated = true
					break
				}
				seenItem[k] = true
				out.Items = append(out.Items, item)
				out.Count++
			}
		}
		if truncated {
			out.Status = "partial"
			out.ErrorCode = "max_items"
			return out
		}
		var next string
		if raw, ok := data["nextCursor"]; ok && string(raw) != "null" {
			if json.Unmarshal(raw, &next) != nil {
				out.Status = "error"
				out.ErrorCode = "invalid_cursor"
				return out
			}
		}
		if next == "" {
			if out.Count == 0 {
				out.Status = "empty"
			} else {
				out.Status = "complete"
			}
			return out
		}
		if out.Count >= c.config.MaxItems {
			out.Status = "partial"
			out.ErrorCode = "max_items"
			return out
		}
		if seenCursor[next] {
			out.Status = "partial"
			out.ErrorCode = "cursor_cycle"
			return out
		}
		seenCursor[next] = true
		cursor = next
	}
	out.Status = "partial"
	out.ErrorCode = "max_pages"
	return out
}

func validItem(key string, item map[string]any) bool {
	if item == nil {
		return false
	}
	field := "name"
	if key == "resources" {
		field = "uri"
	}
	if key == "resourceTemplates" {
		field = "uriTemplate"
	}
	v, ok := item[field].(string)
	return ok && v != ""
}

func publicFindings(c Collections) []Finding {
	var out []Finding
	for _, v := range []struct {
		name     string
		singular string
		plural   string
		coll     Collection
	}{{"tools", "tool", "tools", c.Tools}, {"resources", "resource", "resources", c.Resources}, {"resource_templates", "resource template", "resource templates", c.ResourceTemplates}, {"prompts", "prompt", "prompts", c.Prompts}} {
		if v.coll.Count > 0 && (v.coll.Status == "complete" || v.coll.Status == "partial") {
			label := v.plural
			if v.coll.Count == 1 {
				label = v.singular
			}
			out = append(out, Finding{Code: "public_" + v.name, Summary: fmt.Sprintf("%d %s listed anonymously", v.coll.Count, label), Status: "confirmed", Confidence: "high", Category: "exposure", Severity: "info", EvidenceIDs: v.coll.EvidenceIDs})
		}
	}
	return out
}

func safeError(err error) string {
	if err == nil {
		return ""
	}
	var dns *net.DNSError
	if errors.As(err, &dns) {
		return "dns_failure"
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return "connection_refused"
	}
	var certErr x509.UnknownAuthorityError
	if errors.As(err, &certErr) {
		return "tls_unknown_authority"
	}
	var hostErr x509.HostnameError
	if errors.As(err, &hostErr) {
		return "tls_hostname_mismatch"
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "timeout"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	if errors.Is(err, errCrossOrigin) {
		return "redirect_out_of_scope"
	}
	if errors.Is(err, errBodyLimit) {
		return "body_limit"
	}
	if strings.Contains(err.Error(), "invalid JSON-RPC") || strings.Contains(err.Error(), "JSON-RPC envelope") {
		return "invalid_json_rpc"
	}
	if strings.Contains(err.Error(), "unexpected content type") {
		return "unexpected_content_type"
	}
	if strings.Contains(err.Error(), "empty RPC response") {
		return "empty_response"
	}
	// Transport errors can embed URLs with credentials. Keep only a category.
	return "transport_error"
}

func readOAuthMetadata(ctx context.Context, c *client, header map[string][]string, svc *Service, r *Result) {
	challenge := http.Header(header).Get("Www-Authenticate")
	marker := "resource_metadata=\""
	i := strings.Index(strings.ToLower(challenge), marker)
	if i < 0 {
		return
	}
	rest := challenge[i+len(marker):]
	end := strings.Index(rest, "\"")
	if end < 0 {
		return
	}
	ref, err := url.Parse(rest[:end])
	if err != nil {
		return
	}
	if ref.Scheme != c.endpoint.Scheme || ref.Host != c.endpoint.Host {
		return
	}
	req, err := newMetadataRequest(ctx, ref.String(), c.token)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", c.config.UserAgent)
	if c.pace(ctx) != nil {
		return
	}
	started := time.Now()
	resp, err := c.http.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	r.Metrics.Requests++
	dataBytes, e := io.ReadAll(io.LimitReader(resp.Body, c.config.MaxBody+1))
	obsID := fmt.Sprintf("e%d", len(r.Observations)+1)
	r.Observations = append(r.Observations, Observation{ID: obsID, Phase: "discovery", Method: "GET", Path: ref.EscapedPath(), HTTPStatus: resp.StatusCode, ElapsedMS: time.Since(started).Milliseconds(), BytesReceived: int64(len(dataBytes))})
	r.Metrics.BytesReceived += int64(len(dataBytes))
	if resp.StatusCode != 200 {
		return
	}
	if e != nil || int64(len(dataBytes)) > c.config.MaxBody {
		return
	}
	var data struct {
		Resource             string   `json:"resource"`
		AuthorizationServers []string `json:"authorization_servers"`
		Scopes               []string `json:"scopes_supported"`
	}
	if json.Unmarshal(dataBytes, &data) != nil {
		return
	}
	resource, err := url.Parse(data.Resource)
	if err != nil || resource.Scheme != c.endpoint.Scheme || resource.Host != c.endpoint.Host || strings.TrimSuffix(resource.EscapedPath(), "/") != strings.TrimSuffix(c.endpoint.EscapedPath(), "/") {
		return
	}
	svc.Authentication.OAuthResource = data.Resource
	svc.Authentication.AuthorizationServers = data.AuthorizationServers
	svc.Authentication.Scopes = data.Scopes
	svc.Detection.Status = "suspected"
	svc.Detection.Reason = "OAuth protected resource metadata on target origin"
	svc.Detection.EvidenceIDs = append(svc.Detection.EvidenceIDs, obsID)
	svc.Authentication.EvidenceIDs = []string{obsID}
}
func newMetadataRequest(ctx context.Context, raw, token string) (*http.Request, error) {
	req, e := http.NewRequestWithContext(ctx, "GET", raw, nil)
	if e == nil && token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return req, e
}

func SortResults(results []Result) {
	sort.SliceStable(results, func(i, j int) bool { return results[i].Target.Input < results[j].Target.Input })
}
