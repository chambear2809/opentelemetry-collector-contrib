// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package internal

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtractYANGFromFilesEnforcesResourceLimits(t *testing.T) {
	writeModule := func(t *testing.T, dir, name, contents string) {
		t.Helper()
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(contents), 0o600))
	}
	limits := func() yangModuleLoadLimits {
		return yangModuleLoadLimits{files: 10, walkEntries: 20, fileBytes: 1024, totalBytes: 2048}
	}

	t.Run("valid module", func(t *testing.T) {
		dir := t.TempDir()
		writeModule(t, dir, "valid.yang", "module valid { namespace \"urn:valid\"; prefix v; }")
		parser := NewYANGParser()
		require.NoError(t, parser.extractYANGFromFiles(dir, limits()))
		assert.Contains(t, parser.GetAvailableModules(), "valid")
	})

	t.Run("direct module file", func(t *testing.T) {
		dir := t.TempDir()
		writeModule(t, dir, "direct.yang", "module direct { namespace \"urn:direct\"; prefix d; }")
		parser := NewYANGParser()
		require.NoError(t, parser.extractYANGFromFiles(filepath.Join(dir, "direct.yang"), limits()))
		assert.Contains(t, parser.GetAvailableModules(), "direct")
	})

	t.Run("direct non-YANG file", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "not-a-module.txt")
		require.NoError(t, os.WriteFile(path, []byte("not a module"), 0o600))
		parser := NewYANGParser()
		require.ErrorContains(t, parser.extractYANGFromFiles(path, limits()), "must be a regular .yang file or a directory")
		assert.Empty(t, parser.GetAvailableModules())
	})

	t.Run("direct YANG symlink", func(t *testing.T) {
		dir := t.TempDir()
		writeModule(t, dir, "real.yang", "module real { namespace \"urn:real\"; prefix r; }")
		link := filepath.Join(dir, "link.yang")
		if err := os.Symlink(filepath.Join(dir, "real.yang"), link); err != nil {
			t.Skipf("symbolic links are unavailable: %v", err)
		}
		parser := NewYANGParser()
		require.ErrorContains(t, parser.extractYANGFromFiles(link, limits()), "must be a regular .yang file or a directory")
	})

	t.Run("module replaced after enumeration", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "module.yang")
		writeModule(t, dir, "module.yang", "module original {}")
		expected, err := os.Lstat(path)
		require.NoError(t, err)
		require.NoError(t, os.Rename(path, filepath.Join(dir, "original.yang")))
		require.NoError(t, os.WriteFile(path, []byte("module replacement {}"), 0o600))

		_, err = readBoundedYANGModule(path, expected, 1024)
		require.ErrorContains(t, err, "changed after directory enumeration")
	})

	t.Run("duplicate revisions resolve deterministically", func(t *testing.T) {
		dir := t.TempDir()
		// Create the lexical winner first so filesystem enumeration order cannot
		// accidentally make this test pass by matching filepath.Walk order.
		writeModule(t, dir, "duplicate@2026-01-01.yang", "module duplicate {\n prefix newest;\n}")
		writeModule(t, dir, "duplicate@2025-01-01.yang", "module duplicate {\n prefix older;\n}")
		parser := NewYANGParser()
		require.NoError(t, parser.extractYANGFromFiles(dir, limits()))
		require.Contains(t, parser.modules, "duplicate")
		assert.Equal(t, "newest", parser.modules["duplicate"].Prefix)
	})

	t.Run("single file bytes", func(t *testing.T) {
		dir := t.TempDir()
		writeModule(t, dir, "large.yang", "module large {}")
		parser := NewYANGParser()
		configured := limits()
		configured.fileBytes = 4
		require.ErrorContains(t, parser.extractYANGFromFiles(dir, configured), "hard size limit of 4 bytes")
	})

	t.Run("aggregate bytes across paths", func(t *testing.T) {
		first := t.TempDir()
		second := t.TempDir()
		writeModule(t, first, "first.yang", "module first {}")
		writeModule(t, second, "second.yang", "module second {}")
		parser := NewYANGParser()
		configured := limits()
		configured.totalBytes = int64(len("module first {}") + len("module second {}") - 1)
		require.NoError(t, parser.extractYANGFromFiles(first, configured))
		require.ErrorContains(t, parser.extractYANGFromFiles(second, configured), "hard aggregate size limit")
	})

	t.Run("file count", func(t *testing.T) {
		dir := t.TempDir()
		writeModule(t, dir, "first.yang", "module first {}")
		writeModule(t, dir, "second.yang", "module second {}")
		parser := NewYANGParser()
		configured := limits()
		configured.files = 1
		require.ErrorContains(t, parser.extractYANGFromFiles(dir, configured), "hard file limit of 1")
	})

	t.Run("walk entries in one oversized directory", func(t *testing.T) {
		dir := t.TempDir()
		for i := range 32 {
			writeModule(t, dir, fmt.Sprintf("ignored-%02d.txt", i), "not a module")
		}
		parser := NewYANGParser()
		configured := limits()
		configured.walkEntries = 3
		require.ErrorContains(t, parser.extractYANGFromFiles(dir, configured), "hard entry limit of 3")
		assert.Equal(t, configured.walkEntries+1, parser.walkedEntries, "traversal must stop as soon as the cap is crossed")
	})
}
