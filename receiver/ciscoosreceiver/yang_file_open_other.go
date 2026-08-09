// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !aix && !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !solaris

package ciscoosreceiver

import (
	"fmt"
	"os"
)

// openYANGPath provides a best-effort fallback on platforms without portable
// no-follow and nonblocking open flags. The caller still validates the opened
// descriptor against metadata captured during traversal.
func openYANGPath(path string) (*os.File, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("YANG path %q is a symbolic link", path)
	}
	if !info.IsDir() && !info.Mode().IsRegular() {
		return nil, fmt.Errorf("YANG path %q is not a regular file or directory", path)
	}
	return os.Open(path)
}
