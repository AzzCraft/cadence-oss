package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/AzzCraft/cadence-oss/cadence-core/internal/exactjson"
)

func boundedJSONInput() (any, error) {
	data, err := io.ReadAll(io.LimitReader(os.Stdin, exactjson.MaxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("cannot read contract input")
	}
	return exactjson.Parse(data)
}

func contractsCmd(args []string) {
	if len(args) == 0 || (args[0] != "canonicalize" && args[0] != "validate" && args[0] != "check-action" && args[0] != "check-authorization" && args[0] != "http-inventory" && args[0] != "check-http-coverage") {
		fmt.Fprintln(os.Stderr, "expected: contracts canonicalize, validate --identity <identity>, check-action --probe, check-authorization --probe, http-inventory --probe or check-http-coverage --probe")
		os.Exit(2)
	}
	fs := flag.NewFlagSet("contracts "+args[0], flag.ExitOnError)
	identity := fs.String("identity", "", "explicit supported contract identity")
	probe := fs.Bool("probe", false, "check supplied context without granting authority")
	_ = fs.Parse(args[1:])
	isProbe := args[0] == "check-action" || args[0] == "check-authorization" || args[0] == "http-inventory" || args[0] == "check-http-coverage"
	if (*identity != "das-json-jcs/v1" && args[0] == "canonicalize") || fs.NArg() != 0 || (isProbe && (!*probe || *identity != "")) || (!isProbe && *probe) {
		fmt.Fprintln(os.Stderr, "unsupported codec identity or arguments")
		os.Exit(2)
	}
	var value any
	var err error
	if args[0] == "validate" && (*identity == "das-context-pack/v1" || *identity == "das-context-pack/v2") {
		// Only this explicit catalog-derived reading exchange uses the existing
		// typed catalog budget. Generic codecs and other identities stay fixed.
		data, readErr := io.ReadAll(io.LimitReader(os.Stdin, exactjson.MaxBytes+1))
		if readErr != nil {
			err = readErr
		} else {
			value, err = exactjson.ParseCatalog(data)
		}
	} else {
		value, err = boundedJSONInput()
	}
	if err == nil && args[0] == "validate" {
		value, err = validateIntegrationContract(value, *identity)
	}
	if err == nil && args[0] == "check-action" {
		value, err = checkActionProbe(value)
	}
	if err == nil && args[0] == "check-authorization" {
		value, err = checkAuthorizationProbe(value)
	}
	if err == nil && args[0] == "http-inventory" {
		value, err = httpInventoryProbe(value)
	}
	if err == nil && args[0] == "check-http-coverage" {
		value, err = httpCoverageProbe(value)
	}
	var output []byte
	if err == nil {
		if args[0] == "validate" && (*identity == "das-context-pack/v1" || *identity == "das-context-pack/v2") {
			output, err = exactjson.CanonicalCatalog(value)
		} else {
			output, err = exactjson.Canonical(value)
		}
	}
	if err != nil {
		if args[0] == "check-action" && strings.HasPrefix(err.Error(), "qualification: ") {
			// These fixed reason codes contain no payload, key or artifact bytes.
			fmt.Fprintln(os.Stderr, err.Error())
		} else {
			fmt.Fprintln(os.Stderr, "exact contract encoding rejected")
		}
		os.Exit(1)
	}
	if _, err = os.Stdout.Write(output); err != nil {
		os.Exit(1)
	}
}
