package main

import (
	"runtime/debug"
	"strings"
)

// version is set by the release build with -ldflags "-X main.version=vX.Y.Z".
var version = "dev"

func buildVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "MCPEnum " + version
	}

	build := version
	if build == "dev" {
		build = info.Main.Version
	}
	if build == "" || build == "(devel)" || strings.HasPrefix(build, "v0.0.0-") {
		build = "dev"
	}

	var revision string
	var modified bool
	for _, setting := range info.Settings {
		switch setting.Key {
		case "vcs.revision":
			revision = setting.Value
		case "vcs.modified":
			modified = setting.Value == "true"
		}
	}
	if len(revision) > 12 {
		revision = revision[:12]
	}
	if revision != "" {
		build += " (" + revision
		if modified {
			build += ", modified"
		}
		build += ")"
	} else if modified {
		build += " (modified)"
	}
	return "MCPEnum " + build
}
