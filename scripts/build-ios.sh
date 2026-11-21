#!/usr/bin/env bash
# Builds Bifrost.xcframework (iOS device + simulator) from package ./mobile.
#
#   scripts/build-ios.sh [output-dir]      (default: build/ios)
#
# Needs Xcode and Go. Installs gomobile/gobind in the version pinned in go.mod
# if they are missing or differ. Environment:
#   IOS_MIN   minimum iOS version (default 16.0)
#   TARGETS   gomobile targets (default ios,iossimulator)
set -euo pipefail

cd "$(dirname "$0")/.."
OUT="${1:-build/ios}"
IOS_MIN="${IOS_MIN:-16.0}"
TARGETS="${TARGETS:-ios,iossimulator}"

GOBIN_DIR="$(go env GOPATH)/bin"
export PATH="$GOBIN_DIR:$PATH"

# gomobile, gobind and golang.org/x/mobile/bind must come from the same version.
MOBILE_VERSION="$(go list -m -f '{{.Version}}' golang.org/x/mobile)"
need_install=0
for tool in gomobile gobind; do
	if ! command -v "$tool" >/dev/null 2>&1; then
		need_install=1
	elif ! go version -m "$(command -v "$tool")" | grep -q "golang.org/x/mobile[[:space:]]*$MOBILE_VERSION"; then
		need_install=1
	fi
done
if [ "$need_install" = 1 ]; then
	echo "installing gomobile/gobind $MOBILE_VERSION"
	go install "golang.org/x/mobile/cmd/gomobile@$MOBILE_VERSION" "golang.org/x/mobile/cmd/gobind@$MOBILE_VERSION"
	gomobile init
fi

# The binding must not pull in the relay/agent dependencies (wireguard-go, gVisor).
if go list -deps ./mobile | grep -qE 'wireguard|gvisor'; then
	echo "error: ./mobile depends on wireguard-go or gVisor" >&2
	exit 1
fi

mkdir -p "$OUT"
rm -rf "$OUT/Bifrost.xcframework"
gomobile bind -target="$TARGETS" -iosversion="$IOS_MIN" -trimpath -ldflags="-s -w" \
	-o "$OUT/Bifrost.xcframework" ./mobile

echo "built $OUT/Bifrost.xcframework ($(du -sh "$OUT/Bifrost.xcframework" | cut -f1))"
