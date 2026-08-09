include ../../Makefile.Common

# `nto` is part of Cisco's published Cisco-IOS-XR-nto-misc-oper YANG module
# name, not prose. Keep the vendor identifier exact in the catalog and runtime.
MISSPELL := $(MISSPELL) -i nto

.PHONY: gnmi-catalog
gnmi-catalog:
	$(GOCMD) run ./internal/gnmicataloggen/cmd

.PHONY: gnmi-catalog-check
gnmi-catalog-check:
	$(GOCMD) run ./internal/gnmicataloggen/cmd -check

# MODEL_BUNDLE_DIR must point at a locally supplied Cisco/OpenConfig model
# bundle. The generator never downloads model artifacts.
.PHONY: gnmi-catalog-refresh
gnmi-catalog-refresh:
	$(GOCMD) run ./internal/gnmicataloggen/cmd -verify-model-bundle -model-bundle-dir "$(MODEL_BUNDLE_DIR)"

.PHONY: gnmi-catalog-verify
gnmi-catalog-verify:
	$(GOCMD) run ./internal/gnmicataloggen/cmd -check -verify-model-bundle -model-bundle-dir "$(MODEL_BUNDLE_DIR)"
