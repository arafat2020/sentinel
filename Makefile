.PHONY: build build-dev build-es run clean

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
