// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package internal

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestReadBoundedYANGModuleRejectsFIFOReplacementWithoutBlocking(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "module.yang")
	require.NoError(t, os.WriteFile(path, []byte("module original {}"), 0o600))
	expected, err := os.Lstat(path)
	require.NoError(t, err)
	require.NoError(t, os.Rename(path, filepath.Join(directory, "original.yang")))
	require.NoError(t, unix.Mkfifo(path, 0o600))

	errCh := make(chan error, 1)
	go func() {
		_, readErr := readBoundedYANGModule(path, expected, 1024)
		errCh <- readErr
	}()

	select {
	case err = <-errCh:
		require.ErrorContains(t, err, "not a regular file")
	case <-time.After(time.Second):
		// Release a blocking implementation before failing so the test cannot
		// leak a goroutine into packages that use goleak.
		writerDone := make(chan error, 1)
		go func() {
			fd, openErr := unix.Open(path, unix.O_WRONLY, 0)
			if openErr == nil {
				openErr = unix.Close(fd)
			}
			writerDone <- openErr
		}()
		require.NoError(t, <-writerDone)
		<-errCh
		t.Fatal("opening a FIFO replacement blocked")
	}
}

func TestReadBoundedYANGModuleRejectsSymlinkReplacement(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "module.yang")
	target := filepath.Join(directory, "target.yang")
	require.NoError(t, os.WriteFile(path, []byte("module original {}"), 0o600))
	require.NoError(t, os.WriteFile(target, []byte("module target {}"), 0o600))
	expected, err := os.Lstat(path)
	require.NoError(t, err)
	require.NoError(t, os.Rename(path, filepath.Join(directory, "original.yang")))
	require.NoError(t, os.Symlink(target, path))

	_, err = readBoundedYANGModule(path, expected, 1024)
	require.Error(t, err)
}
