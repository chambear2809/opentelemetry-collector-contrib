// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/gnmicataloggen"
)

func main() {
	manifest := flag.String("manifest", "gnmi_catalog.yaml", "catalog manifest")
	metadata := flag.String("metadata", "metadata.yaml", "component metadata")
	goOutput := flag.String("go-output", "gnmi_catalog_generated.go", "generated Go output")
	coverageOutput := flag.String("coverage-output", "docs/gnmi-coverage.md", "generated coverage documentation")
	metricsOutput := flag.String("metrics-output", "docs/gnmi-metrics.md", "generated metric documentation")
	check := flag.Bool("check", false, "check generated files without writing")
	modelBundleDir := flag.String("model-bundle-dir", "", "local YANG/model bundle directory (never downloaded)")
	verifyModelBundle := flag.Bool("verify-model-bundle", false, "require and verify the local model bundle before generating")
	flag.Parse()

	if *verifyModelBundle && *modelBundleDir == "" {
		_, _ = fmt.Fprintln(os.Stderr, "-verify-model-bundle requires -model-bundle-dir")
		os.Exit(2)
	}
	var catalog *gnmicataloggen.Catalog
	var err error
	if *modelBundleDir != "" {
		catalog, err = gnmicataloggen.LoadWithModelBundle(*manifest, *metadata, *modelBundleDir)
	} else {
		catalog, err = gnmicataloggen.Load(*manifest, *metadata)
	}
	if err == nil && *verifyModelBundle {
		err = gnmicataloggen.VerifyLocalModelBundle(catalog, *modelBundleDir)
	}
	if err == nil {
		var outputs gnmicataloggen.Outputs
		outputs, err = gnmicataloggen.Render(catalog)
		if err == nil {
			err = gnmicataloggen.WriteOrCheck(outputs, gnmicataloggen.OutputPaths{
				Go: *goOutput, Coverage: *coverageOutput, Metrics: *metricsOutput,
			}, *check)
		}
	}
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
