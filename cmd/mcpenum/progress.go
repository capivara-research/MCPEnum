package main

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/capivara-research/MCPEnum/internal/mcprecon"
)

type scanReporter struct {
	mu        sync.Mutex
	out       io.Writer
	progress  bool
	verbose   bool
	active    bool
	completed int
	total     int
}

func newScanReporter(out io.Writer, progressMode string, verbose, quiet bool) *scanReporter {
	showBar := progressMode == "always" || progressMode == "auto" && writerIsTerminal(out)
	if quiet {
		showBar = false
		verbose = false
	}
	r := &scanReporter{out: out, progress: showBar && !verbose, verbose: verbose}
	if !quiet {
		fmt.Fprintln(out, "╭─ >_ MCPEnum ─────────────────────────────────────────╮")
		fmt.Fprintln(out, "│  Model Context Protocol reconnaissance              │")
		fmt.Fprintln(out, "│  inventory · read-only                               │")
		fmt.Fprintln(out, "╰──────────────────────────────────────────────────────╯")
	}
	return r
}

func writerIsTerminal(out io.Writer) bool {
	f, ok := out.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

func (r *scanReporter) event(ev mcprecon.ProgressEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()
	switch ev.Phase {
	case "port-range":
		if r.verbose && ev.Target != "" && (ev.Status == "open" || ev.Total <= 128) {
			fmt.Fprintf(r.out, "PORT  %s: %s\n", safeLine(ev.Target), safeLine(ev.Status))
		}
		if r.progress {
			r.total = ev.Total
			r.completed = ev.Done
			r.draw("Scanning ports")
		}
		return
	case "port":
		if r.verbose && ev.Done > 0 {
			fmt.Fprintf(r.out, "PORT  %d/%d | %s: %s\n", ev.Done, ev.Total, safeLine(ev.Target), safeLine(ev.Status))
		}
		if r.progress {
			r.total = ev.Total
			r.completed = ev.Done
			r.draw("Checking ports")
		}
		return
	case "total":
		r.total = ev.Total
		r.completed = 0
		return
	case "request", "start":
		if r.verbose {
			fmt.Fprintf(r.out, "%s  %s | %s\n", strings.ToUpper(ev.Phase), safeLine(ev.Target), safeLine(ev.Status))
		}
		return
	case "mcp", "http":
		if ev.Done == 0 {
			if r.progress && !r.active {
				r.draw("Preparing scan")
			}
			return
		}
		r.completed++
		label := "Discovering MCP"
		if ev.Phase == "http" {
			label = "Inspecting HTTP"
		}
		if r.verbose {
			fmt.Fprintf(r.out, "%s  %d/%d | %s: %s\n", label, r.completed, r.total, safeLine(ev.Target), safeLine(ev.Status))
		}
		if r.progress {
			r.draw(label)
		}
	}
}

func (r *scanReporter) draw(label string) {
	const width = 24
	filled := 0
	if r.total > 0 {
		filled = r.completed * width / r.total
	}
	if filled > width {
		filled = width
	}
	fmt.Fprintf(r.out, "\r  %-17s %s%s  %d/%d  ", label, strings.Repeat("━", filled), strings.Repeat("─", width-filled), r.completed, r.total)
	r.active = true
}

func (r *scanReporter) finish() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.active {
		r.draw("Complete")
		fmt.Fprintln(r.out)
		r.active = false
	}
}
