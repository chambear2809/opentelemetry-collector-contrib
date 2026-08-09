// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:generate make mdatagen
//go:generate go run ./internal/gnmicataloggen/cmd

// Package ciscoosreceiver provides a receiver for collecting metrics from Cisco network devices via SSH.
package ciscoosreceiver // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver"
