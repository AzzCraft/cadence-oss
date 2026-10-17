package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/AzzCraft/cadence-oss/cadence-core/internal/exactjson"
	"github.com/AzzCraft/cadence-oss/cadence-core/internal/resolver"
)

func resolveCmd(args []string) {
	fs := flag.NewFlagSet("resolve", flag.ExitOnError)
	preview := fs.Bool("preview", false, "evaluate unapproved facts without granting authority")
	checkFacts := fs.Bool("check-approved-facts", false, "check signed facts under supplied context; result remains unapproved preview")
	checkRefs := fs.Bool("check-facts-refs", false, "check exact signed-facts references under supplied context; grants no authority")
	_ = fs.Parse(args)
	selected := 0
	for _, enabled := range []bool{*preview, *checkFacts, *checkRefs} {
		if enabled {
			selected++
		}
	}
	if selected != 1 || fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "select --preview, --check-approved-facts or --check-facts-refs; protected activation is disabled")
		os.Exit(2)
	}
	data, err := io.ReadAll(io.LimitReader(os.Stdin, exactjson.MaxBytes+1))
	var input any
	if err == nil {
		input, err = exactjson.ParseCatalog(data)
		if err == nil {
			object, ok := input.(map[string]any)
			if !ok || (object["contractIdentity"] != "das-bundle-preview-input/v2" &&
				object["contractIdentity"] != "das-bundle-preview-input/v3" &&
				object["contractIdentity"] != "das-approved-facts-preview-input/v1") {
				input, err = exactjson.Parse(data)
			}
		}
	}
	var result map[string]any
	if err == nil {
		if *checkRefs {
			result, err = resolver.CheckApprovedFacts(input)
		} else if *checkFacts {
			result, err = resolver.ApprovedFactsPreview(input)
		} else {
			result, err = resolver.Preview(input)
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "module resolution rejected")
		os.Exit(1)
	}
	if err = json.NewEncoder(os.Stdout).Encode(result); err != nil {
		os.Exit(1)
	}
}
