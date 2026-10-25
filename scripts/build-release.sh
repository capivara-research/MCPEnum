#!/usr/bin/env bash
set -euo pipefail

release_version=${1:?usage: build-release.sh vX.Y.Z}
[[ "$release_version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo 'expected a stable semver tag' >&2; exit 2; }
mkdir -p dist
release_dir=$(pwd)/dist

for target in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64; do
    os=${target%/*}
    arch=${target#*/}
    name="mcpenum_${release_version}_${os}_${arch}"
    tmp=$(mktemp -d)
    binary=mcpenum
    [[ "$os" == windows ]] && binary=mcpenum.exe
    CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -trimpath -ldflags "-s -w -X main.version=${release_version}" -o "$tmp/$binary" ./cmd/mcpenum
    cp LICENSE "$tmp/LICENSE"
    if [[ "$os" == windows ]]; then
        (cd "$tmp" && zip -q "$release_dir/$name.zip" "$binary" LICENSE)
    else
        tar -C "$tmp" -czf "dist/$name.tar.gz" "$binary" LICENSE
    fi
    rm -rf "$tmp"
done
(cd dist && sha256sum mcpenum_* > checksums.txt)
