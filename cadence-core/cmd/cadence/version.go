package main

import (
	_ "embed"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"runtime"
	"runtime/debug"
	"strings"
)

// generatedReleaseVersion comes only from the component VERSION at build time.
//
//go:embed release_version.txt
var generatedReleaseVersion string

func releaseVersion() string { return strings.TrimSpace(generatedReleaseVersion) }

func versionIdentity() map[string]any {
	identity := map[string]any{
		"schemaVersion": "1.0.0", "component": "cadence-oss", "releaseVersion": releaseVersion(),
		"binarySha256": computeSelfBinaryHashOrEmpty(), "goVersion": runtime.Version(),
		"goos": runtime.GOOS, "goarch": runtime.GOARCH, "sourceRevision": "unavailable",
		"sourceModified": true,
	}
	if build, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range build.Settings {
			switch setting.Key {
			case "vcs.revision":
				identity["sourceRevision"] = setting.Value
			case "vcs.modified":
				identity["sourceModified"] = setting.Value != "false"
			}
		}
	}
	return identity
}

func versionCmd(args []string) {
	fs := flag.NewFlagSet("version", flag.ExitOnError)
	machine := fs.Bool("json", false, "print the identity of this executable")
	_ = fs.Parse(args)
	if fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "version does not take positional arguments")
		os.Exit(2)
	}
	if *machine {
		if err := json.NewEncoder(os.Stdout).Encode(versionIdentity()); err != nil {
			fmt.Fprintln(os.Stderr, "cannot write version identity")
			os.Exit(1)
		}
	} else {
		fmt.Printf("cadence %s\n", releaseVersion())
	}
}
