package mcprecon

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestHTTPProfileIsCollectedOncePerOrigin(t *testing.T) {
	var head, options atomic.Int32
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "fixture-http/1")
		w.Header().Set("X-Powered-By", "fixture-framework")
		switch r.Method {
		case http.MethodHead:
			head.Add(1)
			w.Header().Set("Location", "/login?token=private-value")
			w.WriteHeader(http.StatusFound)
		case http.MethodOptions:
			options.Add(1)
			w.Header().Set("Allow", "GET, HEAD, OPTIONS")
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer s.Close()
	cfg := Defaults()
	cfg.Targets = []string{strings.TrimPrefix(s.URL, "http://")}
	cfg.Paths = []string{"/mcp", "/other", "/api/mcp"}
	results, err := Scan(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 3 || head.Load() != 1 || options.Load() != 1 {
		t.Fatalf("results=%d HEAD=%d OPTIONS=%d", len(results), head.Load(), options.Load())
	}
	for _, result := range results {
		p := result.PortInfo
		if p == nil || p.TCPState != "open" || len(p.Probes) != 2 || p.Probes[0].Status != 302 || p.Probes[1].Status != 204 {
			t.Fatalf("bad shared port profile: %+v", p)
		}
		if p.Probes[0].Location != "/login" || p.Probes[0].Server != "fixture-http/1" || p.Probes[1].Allow != "GET, HEAD, OPTIONS" {
			t.Fatalf("missing or unsafe HTTP evidence: %+v", p)
		}
		if result.Metrics.Requests != 2 {
			t.Fatalf("HTTP probes mixed into MCP request count: %+v", result.Metrics)
		}
	}
}

func TestExtendedHTTPProbeBoundsBodyAndExtractsTitle(t *testing.T) {
	var gotRange string
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			gotRange = r.Header.Get("Range")
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, "<html><title>Local &amp; Safe</title>", strings.Repeat("x", 10000))
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer s.Close()
	cfg := Defaults()
	cfg.HTTPProbe = "extended"
	p := probePort(context.Background(), s.URL, cfg)
	if p.TCPState != "open" || len(p.Probes) != 3 || p.Probes[2].Title != "Local & Safe" || gotRange != "bytes=0-4095" {
		t.Fatalf("extended profile: %+v; range=%q", p, gotRange)
	}
}
