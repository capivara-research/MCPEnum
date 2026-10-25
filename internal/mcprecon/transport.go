package mcprecon

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

const modernVersion = "2026-07-28"
const legacyVersion = "2025-11-25"

var errBodyLimit = errors.New("response exceeds body limit")
var errCrossOrigin = errors.New("redirect outside target origin")

type wireReply struct {
	RPC              rpcResponse
	HTTPStatus       int
	Headers          http.Header
	ResolvedPath     string
	ResolvedHasQuery bool
	Bytes            int64
	ElapsedMS        int64
	Err              error
}

type client struct {
	endpoint  *url.URL
	http      *http.Client
	config    Config
	token     string
	version   string
	era       string
	session   string
	legacy    *legacySSE
	seq       int64
	result    *Result
	dialCount *atomic.Int64
}

type legacySSE struct {
	postURL  *url.URL
	endpoint chan *url.URL
	messages chan []byte
	errors   chan error
	cancel   context.CancelFunc
}

// The legacy SSE endpoint event can carry a session identifier in the POST
// URL. Its value is used for requests but must never appear in scan output.
func legacySSESessionState(postURL *url.URL) string {
	if postURL != nil {
		for _, key := range []string{"sessionId", "session_id"} {
			if postURL.Query().Get(key) != "" {
				return "stateful"
			}
		}
	}
	return "unknown"
}

func newClient(rawURL string, cfg Config, token string, result *Result) (*client, error) {
	u, err := url.Parse(rawURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.Fragment != "" {
		return nil, fmt.Errorf("invalid target URL")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.MaxConnsPerHost = 2
	transport.MaxIdleConnsPerHost = 2
	transport.IdleConnTimeout = 10 * time.Second
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: cfg.Insecure} //nolint:gosec -- explicit CLI option
	baseDial := (&net.Dialer{Timeout: time.Duration(cfg.Timeout) * time.Millisecond}).DialContext
	dialCount := &atomic.Int64{}
	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialCount.Add(1)
		return baseDial(ctx, network, addr)
	}
	origin := u.Scheme + "://" + u.Host
	hc := &http.Client{Transport: transport, Timeout: time.Duration(cfg.Timeout) * time.Millisecond,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 2 || req.URL.Scheme+"://"+req.URL.Host != origin {
				return errCrossOrigin
			}
			return nil
		}}
	return &client{endpoint: u, http: hc, config: cfg, token: token, result: result, dialCount: dialCount}, nil
}

func (c *client) close() {
	if c.legacy != nil {
		c.legacy.cancel()
	}
	c.http.CloseIdleConnections()
	c.result.Metrics.TCPConnects += int(c.dialCount.Load())
}

func (c *client) request(ctx context.Context, method string, params map[string]any, phase string) wireReply {
	start := time.Now()
	id := atomic.AddInt64(&c.seq, 1)
	if params == nil {
		params = map[string]any{}
	}
	if c.era == "modern" || method == "server/discover" {
		params["_meta"] = map[string]any{
			"io.modelcontextprotocol/protocolVersion":    modernVersion,
			"io.modelcontextprotocol/clientCapabilities": map[string]any{},
			"io.modelcontextprotocol/clientInfo":         map[string]any{"name": "MCPEnum", "version": "0.1.0"},
		}
	}
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params})
	var reply wireReply
	if c.legacy != nil {
		reply = c.legacyRequest(ctx, id, body)
	} else {
		reply = c.post(ctx, body, method, id)
	}
	reply.ElapsedMS = time.Since(start).Milliseconds()
	c.record(method, phase, reply)
	return reply
}

func (c *client) notify(ctx context.Context, method string) wireReply {
	start := time.Now()
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "method": method})
	var reply wireReply
	if c.legacy != nil {
		reply = c.legacyPost(ctx, body)
	} else {
		reply = c.post(ctx, body, method, 0)
	}
	reply.ElapsedMS = time.Since(start).Milliseconds()
	c.record(method, "inventory", reply)
	return reply
}

func (c *client) post(ctx context.Context, body []byte, method string, id int64) wireReply {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return wireReply{Err: err}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("User-Agent", c.config.UserAgent)
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	if c.session != "" {
		req.Header.Set("Mcp-Session-Id", c.session)
	}
	if c.version != "" {
		req.Header.Set("Mcp-Protocol-Version", c.version)
	}
	if c.era == "modern" || method == "server/discover" {
		req.Header.Set("Mcp-Protocol-Version", modernVersion)
		req.Header.Set("Mcp-Method", method)
	}
	return c.do(req, id)
}

func (c *client) do(req *http.Request, id int64) wireReply {
	if err := c.pace(req.Context()); err != nil {
		return wireReply{Err: err}
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return wireReply{Err: err}
	}
	defer resp.Body.Close()
	out := wireReply{HTTPStatus: resp.StatusCode, Headers: resp.Header.Clone(), ResolvedPath: resp.Request.URL.EscapedPath(), ResolvedHasQuery: resp.Request.URL.RawQuery != ""}
	if id == 0 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return out
	}
	ct, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if ct == "text/event-stream" {
		data, n, err := readSSEMessage(resp.Body, id, c.config.MaxBody)
		out.Bytes = n
		if err != nil {
			out.Err = err
			return out
		}
		out.RPC, out.Err = parseRPC(data, id)
		return out
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, c.config.MaxBody+1))
	out.Bytes = int64(len(data))
	if err != nil {
		out.Err = err
		return out
	}
	if int64(len(data)) > c.config.MaxBody {
		out.Err = errBodyLimit
		return out
	}
	if ct != "application/json" && ct != "" {
		out.Err = fmt.Errorf("unexpected content type: %s", ct)
		return out
	}
	if len(data) == 0 {
		out.Err = errors.New("empty RPC response")
		return out
	}
	out.RPC, out.Err = parseRPC(data, id)
	return out
}

func (c *client) pace(ctx context.Context) error {
	if c.config.gate == nil {
		return nil
	}
	select {
	case <-c.config.gate:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func parseRPC(data []byte, id int64) (rpcResponse, error) {
	var r rpcResponse
	if err := json.Unmarshal(data, &r); err != nil {
		return r, fmt.Errorf("invalid JSON-RPC: %w", err)
	}
	if r.JSONRPC != "2.0" || len(r.ID) == 0 || string(r.ID) != strconv.FormatInt(id, 10) || (len(r.Result) == 0) == (r.Error == nil) {
		return r, errors.New("invalid or mismatched JSON-RPC envelope")
	}
	return r, nil
}

func readSSEMessage(r io.Reader, id int64, limit int64) ([]byte, int64, error) {
	br := bufio.NewReader(r)
	var data []string
	var total int64
	for {
		line, err := br.ReadString('\n')
		total += int64(len(line))
		if total > limit {
			return nil, total, errBodyLimit
		}
		if err != nil && err != io.EOF {
			return nil, total, err
		}
		line = strings.TrimRight(line, "\r\n")
		if strings.HasPrefix(line, "data:") {
			data = append(data, strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " "))
		}
		if line == "" && len(data) > 0 {
			payload := []byte(strings.Join(data, "\n"))
			data = nil
			if response, e := parseRPC(payload, id); e == nil && response.JSONRPC == "2.0" {
				return payload, total, nil
			}
		}
		if err == io.EOF {
			return nil, total, io.ErrUnexpectedEOF
		}
	}
}

func (c *client) record(method, phase string, reply wireReply) {
	if c.config.Progress != nil {
		status := "no HTTP response"
		if reply.HTTPStatus > 0 {
			status = fmt.Sprintf("HTTP %d", reply.HTTPStatus)
		}
		c.config.Progress(ProgressEvent{Phase: "request", Target: c.endpoint.String(), Status: method + ": " + status})
	}
	id := fmt.Sprintf("e%d", len(c.result.Observations)+1)
	status := "invalid"
	if reply.Err == nil && reply.RPC.JSONRPC == "2.0" {
		if reply.RPC.Error != nil {
			status = "error"
		} else {
			status = "success"
		}
	}
	if reply.HTTPStatus == 401 || reply.HTTPStatus == 403 {
		status = "absent"
	}
	if strings.HasPrefix(method, "notifications/") && reply.HTTPStatus >= 200 && reply.HTTPStatus < 300 {
		status = "absent"
	}
	o := Observation{ID: id, Phase: phase, Method: method, Path: c.endpoint.EscapedPath(), HTTPStatus: reply.HTTPStatus, HTTPServer: boundedHeader(reply.Headers.Get("Server")), ContentType: boundedHeader(reply.Headers.Get("Content-Type")), RPCStatus: status, ElapsedMS: reply.ElapsedMS, BytesReceived: reply.Bytes}
	if reply.ResolvedPath != "" && reply.ResolvedPath != o.Path {
		o.ResolvedPath = reply.ResolvedPath
	}
	if reply.RPC.Error != nil {
		o.RPCCode = reply.RPC.Error.Code
	}
	if reply.Err != nil {
		o.ErrorCode = safeError(reply.Err)
	}
	c.result.Observations = append(c.result.Observations, o)
	c.result.Metrics.Requests++
	c.result.Metrics.BytesReceived += reply.Bytes
}

func boundedHeader(value string) string {
	if len(value) > 256 {
		return value[:256]
	}
	return value
}

func (c *client) startLegacySSE(ctx context.Context) error {
	sctx, cancel := context.WithCancel(ctx)
	req, err := http.NewRequestWithContext(sctx, http.MethodGet, c.endpoint.String(), nil)
	if err != nil {
		cancel()
		return err
	}
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("User-Agent", c.config.UserAgent)
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	// A streaming GET must not inherit the per-request client timeout.
	streamClient := *c.http
	streamClient.Timeout = 0
	if err := c.pace(ctx); err != nil {
		cancel()
		return err
	}
	started := time.Now()
	resp, err := streamClient.Do(req)
	if err != nil {
		cancel()
		return err
	}
	c.result.Metrics.Requests++
	c.result.Observations = append(c.result.Observations, Observation{ID: fmt.Sprintf("e%d", len(c.result.Observations)+1), Phase: "discovery", Method: "GET", Path: c.endpoint.EscapedPath(), HTTPStatus: resp.StatusCode, RPCStatus: "absent", ElapsedMS: time.Since(started).Milliseconds()})
	ct, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if resp.StatusCode != 200 || ct != "text/event-stream" {
		resp.Body.Close()
		cancel()
		return fmt.Errorf("legacy SSE unavailable: HTTP %d", resp.StatusCode)
	}
	l := &legacySSE{messages: make(chan []byte, 8), errors: make(chan error, 1), endpoint: make(chan *url.URL, 1), cancel: cancel}
	c.legacy = l
	go func() {
		defer resp.Body.Close()
		br := bufio.NewReader(resp.Body)
		var event string
		var data []string
		var read int64
		for {
			line, e := br.ReadString('\n')
			read += int64(len(line))
			if read > c.config.MaxBody {
				select {
				case l.errors <- errBodyLimit:
				default:
				}
				return
			}
			line = strings.TrimRight(line, "\r\n")
			if strings.HasPrefix(line, "event:") {
				event = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
			}
			if strings.HasPrefix(line, "data:") {
				data = append(data, strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " "))
			}
			if line == "" && len(data) > 0 {
				payload := []byte(strings.Join(data, "\n"))
				if event == "endpoint" {
					u, e := c.endpoint.Parse(string(payload))
					if e != nil || u.Scheme != c.endpoint.Scheme || u.Host != c.endpoint.Host {
						select {
						case l.errors <- errCrossOrigin:
						default:
						}
						return
					}
					select {
					case l.endpoint <- u:
					default:
					}
				} else if event == "message" {
					select {
					case l.messages <- payload:
					case <-sctx.Done():
						return
					}
				}
				event = ""
				data = nil
			}
			if e != nil {
				select {
				case l.errors <- e:
				default:
				}
				return
			}
		}
	}()
	deadline := time.NewTimer(time.Duration(c.config.Timeout) * time.Millisecond)
	defer deadline.Stop()
	for l.postURL == nil {
		select {
		case postURL := <-l.endpoint:
			l.postURL = postURL
		case e := <-l.errors:
			cancel()
			c.legacy = nil
			return e
		case <-deadline.C:
			cancel()
			c.legacy = nil
			return context.DeadlineExceeded
		case <-ctx.Done():
			cancel()
			c.legacy = nil
			return ctx.Err()
		case <-time.After(5 * time.Millisecond):
		}
	}
	return nil
}

func (c *client) legacyPost(ctx context.Context, body []byte) wireReply {
	if c.legacy == nil || c.legacy.postURL == nil {
		return wireReply{Err: errors.New("legacy SSE endpoint unavailable")}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.legacy.postURL.String(), bytes.NewReader(body))
	if err != nil {
		return wireReply{Err: err}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", c.config.UserAgent)
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	if err := c.pace(ctx); err != nil {
		return wireReply{Err: err}
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return wireReply{Err: err}
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	return wireReply{HTTPStatus: resp.StatusCode, Headers: resp.Header.Clone()}
}

func (c *client) legacyRequest(ctx context.Context, id int64, body []byte) wireReply {
	out := c.legacyPost(ctx, body)
	if out.Err != nil || out.HTTPStatus < 200 || out.HTTPStatus >= 300 {
		return out
	}
	for {
		select {
		case data := <-c.legacy.messages:
			r, e := parseRPC(data, id)
			if e == nil {
				out.RPC = r
				out.Bytes = int64(len(data))
				return out
			}
		case e := <-c.legacy.errors:
			out.Err = e
			return out
		case <-ctx.Done():
			out.Err = ctx.Err()
			return out
		}
	}
}
