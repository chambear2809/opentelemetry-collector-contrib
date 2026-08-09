// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package gnmicataloggen

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// VerifyLocalModelBundle verifies every recorded model artifact against a
// caller-supplied directory. It never discovers, downloads, or follows a URL.
// os.Root keeps relative module paths inside the supplied bundle directory.
func VerifyLocalModelBundle(catalog *Catalog, bundleDir string) error {
	if catalog == nil {
		return errors.New("catalog cannot be nil")
	}
	if strings.TrimSpace(bundleDir) == "" {
		return errors.New("local model bundle directory cannot be empty")
	}
	verified := 0
	for _, bundle := range catalog.Manifest.ModelBundles {
		if bundle.Disposition != "verified" {
			continue
		}
		if _, verifyErr := loadVerifiedModelSchemas(bundleDir, bundle); verifyErr != nil {
			return verifyErr
		}
		verified += len(bundle.Modules)
	}
	if verified == 0 {
		return errors.New("catalog has no recorded model modules to verify; add provenance from a supplied bundle before refreshing")
	}
	return nil
}

func verifyModelModuleContent(module ModelModule, raw []byte) error {
	digest := sha256.Sum256(raw)
	got := hex.EncodeToString(digest[:])
	if got != module.SHA256 {
		return fmt.Errorf("model module %q SHA-256 mismatch for %q: got %s, want %s", module.ID, module.File, got, module.SHA256)
	}
	modulePattern := regexp.MustCompile(`(?m)\b(?:module|submodule)\s+` + regexp.QuoteMeta(module.Name) + `\s*\{`)
	if !modulePattern.Match(raw) {
		return fmt.Errorf("model module %q does not declare recorded name %q", module.ID, module.Name)
	}
	revisionPattern := regexp.MustCompile(`(?m)\brevision\s+["']?` + regexp.QuoteMeta(module.Revision) + `["']?\s*(?:\{|;)`)
	if !revisionPattern.Match(raw) {
		return fmt.Errorf("model module %q does not declare recorded revision %q", module.ID, module.Revision)
	}
	return nil
}
