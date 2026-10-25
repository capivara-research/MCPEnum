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
	mu       sync.Mutex
	out      io.Writer
	progress bool
	verbose  bool
	active   bool
	phase    string
}

func newScanReporter(out io.Writer, progressMode string, verbose, quiet bool) *scanReporter {
	showBar := progressMode == "always" || progressMode == "auto" && writerIsTerminal(out)
	if quiet {
		showBar = false
		verbose = false
	}
	r := &scanReporter{out: out, progress: showBar && !verbose, verbose: verbose}
	if !quiet {
		fmt.Fprintln(out, "MCPEnum  |  MCP discovery and inventory")
		fmt.Fprintln(out, "HTTP service evidence is separate from MCP confirmation.")
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
	if ev.Phase == "request" || ev.Phase == "start" {
		if r.verbose {
			fmt.Fprintf(r.out, "%s  %s | %s\n", strings.ToUpper(ev.Phase), safeLine(ev.Target), safeLine(ev.Status))
		}
		return
	}
	if r.active && ev.Phase != r.phase {
		fmt.Fprintln(r.out)
		r.active = false
	}
	r.phase = ev.Phase
	label := "MCP candidates"
	if ev.Phase == "http" {
		label = "HTTP origins"
	}
	if r.verbose && ev.Done > 0 {
		fmt.Fprintf(r.out, "%s [%d/%d] %s: %s\n", label, ev.Done, ev.Total, safeLine(ev.Target), safeLine(ev.Status))
	}
	if r.progress {
		width := 24
		filled := 0
		if ev.Total > 0 {
			filled = ev.Done * width / ev.Total
		}
		fmt.Fprintf(r.out, "\r%s [%s%s] %d/%d", label, strings.Repeat("#", filled), strings.Repeat("-", width-filled), ev.Done, ev.Total)
		r.active = true
	}
}

func (r *scanReporter) finish() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.active {
		fmt.Fprintln(r.out)
		r.active = false
	}
}
