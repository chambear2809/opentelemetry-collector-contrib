// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package ciscoosreceiver

import (
	"os"

	"golang.org/x/sys/unix"
)

// openYANGPath opens a configured YANG path without following a final symlink.
// O_NONBLOCK ensures that a regular file replaced with a FIFO cannot stall
// receiver startup before the opened descriptor is validated.
func openYANGPath(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return nil, os.ErrInvalid
	}
	return file, nil
}
