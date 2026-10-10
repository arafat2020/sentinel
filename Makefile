.PHONY: build build-dev build-es run clean generate generate-check

# Development build: no ES entitlement, ad-hoc signed.
# Run with sudo for full DNS capture; without sudo for process/network/file only.
build build-dev:
	go build -o sentinel ./cmd/sentinel
	codesign --force --sign - sentinel

# Production build: Endpoint Security enabled.
# Requires -tags es and a valid Apple Developer ID certificate.
# Replace YOUR_DEVELOPER_ID with: codesign -vv sentinel after signing.
build-es:
	go build -tags es -o sentinel ./cmd/sentinel
	@echo "Sign with a real Developer ID:"
	@echo "  codesign --force --sign \"Developer ID Application: YOUR_NAME (TEAMID)\" \\"
	@echo "           --entitlements entitlements.plist sentinel"

run:
	sudo ./sentinel

clean:
	rm -f sentinel

# Recompile the eBPF programs and regenerate their Go bindings (Linux only).
# The results are committed, so an ordinary build needs none of this.
# Requires clang-18 and llvm-strip-18; the headers are in the repository.
generate:
	cd internal/collector/process/procevents && go generate ./...

# Fail if the committed eBPF objects and bindings are not what the sources
# produce. CI runs this.
generate-check: generate
	git diff --exit-code -- internal/collector/process/procevents
