// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build darwin || linux

package gnmi

import "syscall"

func readScaleProcessCPU() (float64, bool) {
	var usage syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &usage); err != nil {
		return 0, false
	}
	return scaleTimevalSeconds(usage.Utime) + scaleTimevalSeconds(usage.Stime), true
}

func scaleTimevalSeconds(value syscall.Timeval) float64 {
	return float64(value.Sec) + float64(value.Usec)/1_000_000
}
