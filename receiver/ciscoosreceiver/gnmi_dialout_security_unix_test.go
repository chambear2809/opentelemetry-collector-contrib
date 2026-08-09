// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package ciscoosreceiver

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestPreflightReadableYANGFileRejectsFIFOReplacementWithoutBlocking(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "module.yang")
	require.NoError(t, os.WriteFile(path, []byte("module original {}"), 0o600))
	expected, err := os.Lstat(path)
	require.NoError(t, err)
	require.NoError(t, os.Rename(path, filepath.Join(directory, "original.yang")))
	require.NoError(t, unix.Mkfifo(path, 0o600))

	type preflightResult struct {
		err        error
		totalBytes int64
	}
	resultCh := make(chan preflightResult, 1)
	go func() {
		var totalBytes int64
		preflightErr := preflightReadableYANGFile(path, expected, 1024, 2048, &totalBytes)
		resultCh <- preflightResult{err: preflightErr, totalBytes: totalBytes}
	}()

	select {
	case result := <-resultCh:
		require.ErrorContains(t, result.err, "not a regular file")
		assert.Zero(t, result.totalBytes)
	case <-time.After(time.Second):
		// Release a blocking implementation before failing so goleak can still
		// verify that receiver startup left no goroutine behind.
		writerDone := make(chan error, 1)
		go func() {
			fd, openErr := unix.Open(path, unix.O_WRONLY, 0)
			if openErr == nil {
				openErr = unix.Close(fd)
			}
			writerDone <- openErr
		}()
		require.NoError(t, <-writerDone)
		<-resultCh
		t.Fatal("opening a FIFO replacement blocked")
	}
}

func TestPreflightReadableYANGFileRejectsSymlinkReplacement(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "module.yang")
	target := filepath.Join(directory, "target.yang")
	require.NoError(t, os.WriteFile(path, []byte("module original {}"), 0o600))
	require.NoError(t, os.WriteFile(target, []byte("module target {}"), 0o600))
	expected, err := os.Lstat(path)
	require.NoError(t, err)
	require.NoError(t, os.Rename(path, filepath.Join(directory, "original.yang")))
	require.NoError(t, os.Symlink(target, path))

	var totalBytes int64
	err = preflightReadableYANGFile(path, expected, 1024, 2048, &totalBytes)
	require.Error(t, err)
	assert.Zero(t, totalBytes)
}
