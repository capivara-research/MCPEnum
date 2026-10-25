package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
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
		os.Exit(2)
	}
}

func run(args []string, out, errout io.Writer) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" {
		usage(out)
		return nil
	}
	if args[0] != "scan" {
		return errors.New("expected 'scan' subcommand")
	}
	cfg := mcprecon.Defaults()
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(errout)
	var urls, targets, paths values
	var targetsFile, pathsFile, ports, tokenEnv, tokenFile, format, profile, pathProfile, colorMode string
	var showSchemas bool
	fs.Var(&urls, "url", "explicit MCP URL (repeatable)")
	fs.Var(&targets, "target", "host or host:port (repeatable)")
	fs.Var(&paths, "path", "candidate path for --target (repeatable)")
	fs.StringVar(&pathsFile, "paths-file", "", "file with one candidate path per line; combines with --path and replaces the built-in profile")
	fs.StringVar(&pathProfile, "path-profile", "standard", "candidate paths for --target: standard, broad, or extensive")
	fs.StringVar(&targetsFile, "targets-file", "", "file with one host, host:port or URL per line")
	fs.StringVar(&ports, "ports", "443,3000,8000,8080", "TCP ports for --target")
	fs.StringVar(&tokenEnv, "token-env", "", "environment variable holding Bearer token")
	fs.StringVar(&tokenFile, "token-file", "", "file holding Bearer token")
	fs.StringVar(&format, "format", "text", "text, json, or jsonl")
	fs.StringVar(&colorMode, "color", "auto", "terminal colors: auto, always, or never (text only)")
	fs.BoolVar(&showSchemas, "schemas", false, "show full tool input schemas in text output")
	fs.StringVar(&profile, "profile", "inventory", "scan profile (inventory)")
	fs.StringVar(&cfg.UserAgent, "user-agent", cfg.UserAgent, "HTTP User-Agent for traffic identification")
	fs.IntVar(&cfg.Timeout, "timeout-ms", cfg.Timeout, "per-request timeout in milliseconds")
	fs.IntVar(&cfg.Budget, "budget-ms", cfg.Budget, "per-endpoint budget in milliseconds")
	fs.IntVar(&cfg.Workers, "workers", cfg.Workers, "parallel endpoint workers")
	fs.IntVar(&cfg.Rate, "rate", 0, "maximum HTTP requests per second across targets (0: no pacing)")
	fs.BoolVar(&cfg.AllowCIDR, "allow-cidr", false, "allow CIDR target expansion")
	fs.IntVar(&cfg.MaxHosts, "max-hosts", cfg.MaxHosts, "maximum hosts expanded from a CIDR")
	fs.IntVar(&cfg.MaxPages, "max-pages", cfg.MaxPages, "maximum pages per collection")
	fs.IntVar(&cfg.MaxItems, "max-items", cfg.MaxItems, "maximum items per collection")
	fs.Int64Var(&cfg.MaxBody, "max-body", cfg.MaxBody, "maximum response bytes")
	fs.BoolVar(&cfg.Insecure, "insecure", false, "disable TLS certificate verification")
	if err := fs.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if len(fs.Args()) != 0 {
		return errors.New("unexpected positional arguments")
	}
	if format != "text" && format != "json" && format != "jsonl" {
		return errors.New("format must be text, json, or jsonl")
	}
	if colorMode != "auto" && colorMode != "always" && colorMode != "never" {
		return errors.New("color must be auto, always, or never")
	}
	if profile != "inventory" {
		return errors.New("only inventory profile is implemented")
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
	if pathProfile == "broad" {
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
	parsed, e := parsePorts(ports)
	if e != nil {
		return e
	}
	cfg.Ports = parsed
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
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	results, e := mcprecon.Scan(ctx, cfg)
	if e != nil {
		return e
	}
	switch format {
	case "json":
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		if len(results) == 1 {
			return enc.Encode(results[0])
		}
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
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	return out, nil
}

func usage(w io.Writer) {
	fmt.Fprintln(w, "MCPEnum — read-only MCP endpoint discovery and enumeration\n\nUsage:\n  mcpenum scan --url http://127.0.0.1:8000/mcp [--format text|json|jsonl]\n  mcpenum scan --target host.example --ports 443,8000 [--path-profile extensive]\n  mcpenum scan --target host.example --paths-file paths.txt\n\nRun mcpenum scan --help for all options.")
}
