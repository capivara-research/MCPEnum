package mcprecon

import (
	"context"
	"crypto/tls"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var htmlTitle = regexp.MustCompile(`(?is)<title\b[^>]*>(.*?)</title\s*>`)

// Profile each origin once even when many candidate paths share its port.
func attachPortProfiles(ctx context.Context, results []Result, cfg Config) {
	type group struct {
		origin  string
		indices []int
	}
	var groups []group
	seen := make(map[string]int)
	for i := range results {
		u, err := url.Parse(results[i].Target.Input)
		if err != nil || u.Scheme == "" || u.Host == "" {
			continue
		}
		origin := u.Scheme + "://" + u.Host
		if j, ok := seen[origin]; ok {
			groups[j].indices = append(groups[j].indices, i)
		} else {
			seen[origin] = len(groups)
			groups = append(groups, group{origin: origin, indices: []int{i}})
		}
	}
	profiles := make([]*PortInfo, len(groups))
	jobs := make(chan int)
	var wg sync.WaitGroup
	var completed atomic.Int64
	if cfg.Progress != nil {
		cfg.Progress(ProgressEvent{Phase: "http", Done: 0, Total: len(groups)})
	}
	workers := cfg.Workers
	if workers > len(groups) {
		workers = len(groups)
	}
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				if allGroupConnectionRefused(results, groups[j].indices) {
					profiles[j] = &PortInfo{Origin: groups[j].origin, TCPState: "closed", Probes: []HTTPProbeInfo{}}
				} else {
					profiles[j] = probePort(ctx, groups[j].origin, cfg)
					if profiles[j].TCPState == "unknown" && groupHasHTTPResponse(results, groups[j].indices) {
						profiles[j].TCPState = "open"
					}
				}
				if cfg.Progress != nil {
					cfg.Progress(ProgressEvent{Phase: "http", Done: int(completed.Add(1)), Total: len(groups), Target: groups[j].origin, Status: profiles[j].TCPState})
				}
			}
		}()
	}
	for j := range groups {
		jobs <- j
	}
	close(jobs)
	wg.Wait()
	for j := range groups {
		for _, i := range groups[j].indices {
			results[i].PortInfo = profiles[j]
		}
	}
}

func groupHasHTTPResponse(results []Result, indices []int) bool {
	for _, i := range indices {
		for _, obs := range results[i].Observations {
			if obs.HTTPStatus > 0 {
				return true
			}
		}
	}
	return false
}

func allGroupConnectionRefused(results []Result, indices []int) bool {
	if len(indices) == 0 {
		return false
	}
	for _, i := range indices {
		if !allConnectionRefused(results[i].Observations) {
			return false
		}
	}
	return true
}

func allConnectionRefused(observations []Observation) bool {
	if len(observations) == 0 {
		return false
	}
	for _, obs := range observations {
		if obs.ErrorCode != "connection_refused" {
			return false
		}
	}
	return true
}

func probePort(ctx context.Context, origin string, cfg Config) *PortInfo {
	profileStart := time.Now()
	profile := &PortInfo{Origin: origin, TCPState: "unknown", Probes: []HTTPProbeInfo{}}
	defer func() { profile.DurationMS = time.Since(profileStart).Milliseconds() }()
	probeTimeout := time.Duration(cfg.Timeout) * time.Millisecond
	if probeTimeout > 1500*time.Millisecond {
		probeTimeout = 1500 * time.Millisecond
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.MaxResponseHeaderBytes = 16 << 10
	transport.ResponseHeaderTimeout = probeTimeout
	transport.DisableCompression = true
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: cfg.Insecure} //nolint:gosec -- explicit CLI option
	transport.DialContext = (&net.Dialer{Timeout: probeTimeout}).DialContext
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	methods := []string{http.MethodHead, http.MethodOptions}
	if cfg.HTTPProbe == "extended" {
		methods = append(methods, http.MethodGet)
	}
	for _, method := range methods {
		if ctx.Err() != nil {
			break
		}
		probeCtx, cancel := context.WithTimeout(ctx, probeTimeout)
		if cfg.gate != nil {
			select {
			case <-cfg.gate:
			case <-probeCtx.Done():
				cancel()
				return profile
			}
		}
		started := time.Now()
		p := HTTPProbeInfo{Method: method, Path: "/"}
		req, err := http.NewRequestWithContext(probeCtx, method, origin+"/", nil)
		if err == nil {
			req.Header.Set("User-Agent", cfg.UserAgent)
			req.Header.Set("Accept-Encoding", "identity")
			if method == http.MethodGet {
				req.Header.Set("Range", "bytes=0-4095")
			}
			var resp *http.Response
			resp, err = client.Do(req)
			if err == nil {
				p.Status = resp.StatusCode
				p.StatusText = http.StatusText(resp.StatusCode)
				p.Protocol = resp.Proto
				p.Server = boundedHTTPValue(resp.Header.Get("Server"))
				p.PoweredBy = boundedHTTPValue(resp.Header.Get("X-Powered-By"))
				p.ContentType = boundedHTTPValue(resp.Header.Get("Content-Type"))
				p.ContentLength = boundedHTTPValue(resp.Header.Get("Content-Length"))
				p.Date = boundedHTTPValue(resp.Header.Get("Date"))
				p.Via = boundedHTTPValue(resp.Header.Get("Via"))
				p.Allow = boundedHTTPValue(resp.Header.Get("Allow"))
				p.Location = safeHTTPLocation(resp.Header.Get("Location"))
				p.WWWAuthenticate = boundedHTTPValue(resp.Header.Get("WWW-Authenticate"))
				if resp.TLS != nil {
					profile.TLSVersion = tls.VersionName(resp.TLS.Version)
				}
				if method == http.MethodGet && strings.HasPrefix(strings.ToLower(p.ContentType), "text/html") {
					body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
					if match := htmlTitle.FindSubmatch(body); len(match) == 2 {
						p.Title = boundedHTTPValue(html.UnescapeString(strings.Join(strings.Fields(string(match[1])), " ")))
					}
				}
				resp.Body.Close()
				profile.TCPState = "open"
			}
		}
		if err != nil {
			p.ErrorCode = safeError(err)
		}
		p.ElapsedMS = time.Since(started).Milliseconds()
		profile.Probes = append(profile.Probes, p)
		cancel()
	}
	if profile.TCPState == "unknown" && allHTTPProbesRefused(profile.Probes) {
		profile.TCPState = "closed"
	}
	return profile
}

func allHTTPProbesRefused(probes []HTTPProbeInfo) bool {
	if len(probes) == 0 {
		return false
	}
	for _, probe := range probes {
		if probe.ErrorCode != "connection_refused" {
			return false
		}
	}
	return true
}

func boundedHTTPValue(value string) string {
	value = strings.Join(strings.Fields(value), " ")
	if len(value) > 240 {
		value = value[:240]
	}
	return value
}

func safeHTTPLocation(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || raw == "" {
		return ""
	}
	u.User = nil
	u.RawQuery = ""
	u.Fragment = ""
	return boundedHTTPValue(u.String())
}
