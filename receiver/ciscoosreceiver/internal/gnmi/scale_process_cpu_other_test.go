// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !darwin && !linux

package gnmi

func readScaleProcessCPU() (float64, bool) { return 0, false }
