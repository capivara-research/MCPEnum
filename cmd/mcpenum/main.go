package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/capivara-research/MCPEnum/internal/mcprecon"
)

type values []string

func (v *values) String() string     { return strings.Join(*v, ",") }
func (v *values) Set(x string) error { *v = append(*v, x); return nil }

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "mcpenum:", err)
		if errors.Is(err, context.Canceled) {
			os.Exit(130)
		}
		os.Exit(2)
	}
}

func run(args []string, out, errout io.Writer) error {
	if len(args) == 0 || args[0] == "help" {
		usage(out)
		return nil
	}
	if len(args) == 1 && args[0] == "--version" {
		fmt.Fprintln(out, buildVersion())
		return nil
	}
	cfg := mcprecon.Defaults()
	fs := flag.NewFlagSet("mcpenum", flag.ContinueOnError)
	fs.SetOutput(errout)
	var urls, targets, paths values
	var targetsFile, pathsFile, ports, scanPorts, tokenEnv, tokenFile, format, pathProfile, colorMode string
	var showSchemas, verbose, quiet, noPortScan bool
	var progressMode string
	fs.Var(&urls, "url", "explicit MCP URL (repeatable)")
	fs.Var(&targets, "target", "host or host:port (repeatable)")
	fs.Var(&paths, "path", "candidate path for --target (repeatable)")
	fs.StringVar(&pathsFile, "paths-file", "", "file with one candidate path per line; combines with --path and replaces the built-in profile")
	fs.StringVar(&pathProfile, "path-profile", "broad", "candidate paths for --target: standard (9), broad (17, default), or extensive (28)")
	fs.StringVar(&targetsFile, "targets-file", "", "file with one host, host:port or URL per line")
	fs.StringVar(&ports, "ports", "", "limit --target HOST to selected TCP ports, e.g. 80,443,8000")
	fs.StringVar(&scanPorts, "scan-ports", "", "TCP range for --target HOST (default 1-65535)")
	fs.BoolVar(&noPortScan, "no-port-scan", false, "skip TCP and HTTP port checks; requires an exact URL or selected target port")
	fs.IntVar(&cfg.PortScanWorkers, "port-workers", cfg.PortScanWorkers, "concurrent TCP checks for --scan-ports")
	fs.IntVar(&cfg.PortScanTimeout, "port-timeout-ms", cfg.PortScanTimeout, "per-port TCP timeout for --scan-ports")
	fs.IntVar(&cfg.PortScanRate, "port-rate", cfg.PortScanRate, "maximum TCP connects per second (0: no pacing)")
	fs.StringVar(&cfg.Scheme, "scheme", cfg.Scheme, "scheme for --target: auto (detect TLS on open ports), http, or https")
	fs.StringVar(&tokenEnv, "token-env", "", "environment variable holding Bearer token")
	fs.StringVar(&tokenFile, "token-file", "", "file holding Bearer token")
	fs.StringVar(&format, "format", "text", "text, json, or jsonl")
	fs.StringVar(&colorMode, "color", "auto", "terminal colors: auto, always, or never (text only)")
	fs.BoolVar(&showSchemas, "schemas", false, "show full tool input schemas in text output")
	fs.BoolVar(&verbose, "verbose", false, "show each completed candidate on stderr")
	fs.BoolVar(&quiet, "quiet", false, "suppress banner and scan progress")
	fs.StringVar(&progressMode, "progress", "auto", "progress on stderr: auto, always, or never")
	fs.StringVar(&cfg.HTTPProbe, "http-probe", cfg.HTTPProbe, "HTTP port metadata: off, basic (HEAD and OPTIONS), or extended (also bounded GET)")
	fs.StringVar(&cfg.UserAgent, "user-agent", cfg.UserAgent, "HTTP User-Agent for traffic identification")
	fs.IntVar(&cfg.Timeout, "timeout-ms", cfg.Timeout, "per-request timeout in milliseconds")
	fs.IntVar(&cfg.Budget, "budget-ms", cfg.Budget, "per-endpoint budget in milliseconds")
	fs.IntVar(&cfg.Workers, "workers", cfg.Workers, "parallel endpoint workers")
	fs.IntVar(&cfg.Rate, "rate", cfg.Rate, "maximum HTTP requests per second across targets (0: no pacing)")
	fs.BoolVar(&cfg.AllowCIDR, "allow-cidr", false, "allow CIDR target expansion")
	fs.IntVar(&cfg.MaxHosts, "max-hosts", cfg.MaxHosts, "maximum hosts expanded from a CIDR")
	fs.IntVar(&cfg.MaxPages, "max-pages", cfg.MaxPages, "maximum pages per collection")
	fs.IntVar(&cfg.MaxItems, "max-items", cfg.MaxItems, "maximum items per collection")
	fs.Int64Var(&cfg.MaxBody, "max-body", cfg.MaxBody, "maximum response bytes")
	fs.BoolVar(&cfg.Insecure, "insecure", false, "disable TLS certificate verification")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if len(fs.Args()) != 0 {
		return fmt.Errorf("unexpected positional argument %q; run mcpenum --help", fs.Args()[0])
	}
	var portsSet, scanPortsSet, httpProbeExplicit bool
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "ports":
			portsSet = true
		case "scan-ports":
			scanPortsSet = true
		case "http-probe":
			httpProbeExplicit = true
		}
	})
	if format != "text" && format != "json" && format != "jsonl" {
		return errors.New("format must be text, json, or jsonl")
	}
	if progressMode != "auto" && progressMode != "always" && progressMode != "never" {
		return errors.New("progress must be auto, always, or never")
	}
	if quiet && verbose {
		return errors.New("--quiet and --verbose cannot be combined")
	}
	if colorMode != "auto" && colorMode != "always" && colorMode != "never" {
		return errors.New("color must be auto, always, or never")
	}
	if pathProfile != "standard" && pathProfile != "broad" && pathProfile != "extensive" {
		return errors.New("path-profile must be standard, broad, or extensive")
	}
	if tokenEnv != "" && tokenFile != "" {
		return errors.New("choose --token-env or --token-file")
	}
	if tokenEnv != "" {
		cfg.Token = os.Getenv(tokenEnv)
		if cfg.Token == "" {
			return errors.New("token environment variable is empty")
		}
	}
	if tokenFile != "" {
		b, e := os.ReadFile(tokenFile)
		if e != nil {
			return e
		}
		cfg.Token = strings.TrimSpace(string(b))
		if cfg.Token == "" {
			return errors.New("token file is empty")
		}
	}
	cfg.URLs = urls
	cfg.Targets = targets
	if pathProfile == "standard" {
		cfg.Paths = mcprecon.StandardPaths()
	} else if pathProfile == "broad" {
		cfg.Paths = mcprecon.BroadPaths()
	} else if pathProfile == "extensive" {
		cfg.Paths = mcprecon.ExtensivePaths()
	}
	if pathsFile != "" {
		file, e := os.Open(pathsFile)
		if e != nil {
			return e
		}
		defer file.Close()
		scanner := bufio.NewScanner(file)
		scanner.Buffer(make([]byte, 1024), 4096)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			paths = append(paths, line)
			if len(paths) > 128 {
				return errors.New("too many custom paths (maximum 128)")
			}
		}
		if e := scanner.Err(); e != nil {
			return e
		}
	}
	if len(paths) > 0 {
		cfg.Paths = paths
	} else if pathsFile != "" {
		return errors.New("paths file has no candidate paths")
	}
	if portsSet {
		parsed, e := parsePorts(ports)
		if e != nil {
			return e
		}
		cfg.Ports = parsed
		cfg.PortScanStart, cfg.PortScanEnd = 0, 0
	}
	if scanPortsSet {
		if portsSet {
			return errors.New("choose --ports or --scan-ports, not both")
		}
		if noPortScan {
			return errors.New("--no-port-scan cannot be combined with --scan-ports")
		}
		parts := strings.Split(scanPorts, "-")
		if len(parts) != 2 {
			return errors.New("--scan-ports expects START-END")
		}
		first, e1 := strconv.Atoi(parts[0])
		last, e2 := strconv.Atoi(parts[1])
		if e1 != nil || e2 != nil || first < 1 || last > 65535 || last < first {
			return errors.New("invalid --scan-ports range")
		}
		cfg.PortScanStart, cfg.PortScanEnd = first, last
	}
	if targetsFile != "" {
		file, e := os.Open(targetsFile)
		if e != nil {
			return e
		}
		defer file.Close()
		scanner := bufio.NewScanner(file)
		scanner.Buffer(make([]byte, 64*1024), 1024*1024)
		for scanner.Scan() {
			line := scanner.Text()
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if strings.HasPrefix(line, "http://") || strings.HasPrefix(line, "https://") {
				cfg.URLs = append(cfg.URLs, line)
			} else {
				cfg.Targets = append(cfg.Targets, line)
			}
		}
		if e := scanner.Err(); e != nil {
			return e
		}
	}
	if noPortScan {
		cfg.PortDiscovery = false
		cfg.PortScanStart, cfg.PortScanEnd = 0, 0
		if !portsSet {
			for _, target := range cfg.Targets {
				if _, _, err := net.SplitHostPort(target); err != nil {
					return fmt.Errorf("--no-port-scan needs --ports or a host:port target (got %q)", target)
				}
			}
		}
	}
	if portsSet || scanPortsSet {
		bare := false
		for _, target := range cfg.Targets {
			if _, _, err := net.SplitHostPort(target); err != nil {
				bare = true
				break
			}
		}
		if !bare {
			return errors.New("--ports and --scan-ports require a host target without an explicit port")
		}
	}
	if !httpProbeExplicit && (noPortScan || len(cfg.Targets) == 0) {
		cfg.HTTPProbe = "off"
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	reporter := newScanReporter(errout, progressMode, verbose, quiet)
	cfg.Progress = reporter.event
	results, e := mcprecon.Scan(ctx, cfg)
	reporter.finish()
	if e != nil {
		return e
	}
	switch format {
	case "json":
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(results)
	case "jsonl":
		enc := json.NewEncoder(out)
		for _, r := range results {
			if e := enc.Encode(r); e != nil {
				return e
			}
		}
		return nil
	case "text":
		color := terminalColorEnabled(colorMode, out)
		printResultsStyled(out, results, showSchemas, color)
		return nil
	default:
		return errors.New("format must be text, json, or jsonl")
	}
}

func parsePorts(s string) ([]int, error) {
	seen := map[int]bool{}
	var out []int
	for _, part := range strings.Split(s, ",") {
		if part == "" {
			return nil, errors.New("empty port")
		}
		bounds := strings.Split(part, "-")
		if len(bounds) > 2 {
			return nil, errors.New("invalid port range")
		}
		first, e := strconv.Atoi(bounds[0])
		if e != nil {
			return nil, e
		}
		last := first
		if len(bounds) == 2 {
			last, e = strconv.Atoi(bounds[1])
			if e != nil {
				return nil, e
			}
		}
		if first < 1 || last > 65535 || last < first || last-first > 1024 {
			return nil, errors.New("invalid or excessive port range")
		}
		for p := first; p <= last; p++ {
			if !seen[p] {
				if len(out) >= 128 {
					return nil, errors.New("too many selected ports (maximum 128)")
				}
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	return out, nil
}

func usage(w io.Writer) {
	fmt.Fprintln(w, "MCPEnum — read-only MCP endpoint discovery and enumeration\n\nUsage:\n  mcpenum --target host.example                 # scan TCP ports 1-65535\n  mcpenum --target host.example:8000            # check one port\n  mcpenum --target host.example --ports 80,443  # limit ports\n  mcpenum --url http://127.0.0.1:8000/mcp       # exact endpoint\n\nRun mcpenum --help for all options or mcpenum --version for build information.")
}
