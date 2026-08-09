// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/metricschemagen"
)

func main() {
	metadataPath := flag.String("metadata", "metadata.yaml", "path to the receiver metadata catalog")
	outputPath := flag.String("output", "generated_metric_schema.go", "path to the generated Go registry")
	flag.Parse()

	metadata, err := os.ReadFile(filepath.Clean(*metadataPath))
	if err != nil {
		fatalf("read metadata: %v", err)
	}
	generated, err := metricschemagen.Generate(metadata)
	if err != nil {
		fatalf("generate metric schema: %v", err)
	}
	// The generated Go source is intentionally repository-readable.
	if err := os.WriteFile(filepath.Clean(*outputPath), generated, 0o644); err != nil { //nolint:gosec
		fatalf("write generated metric schema: %v", err)
	}
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
