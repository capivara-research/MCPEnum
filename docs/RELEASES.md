# Installing and verifying a release

Each tagged release includes Linux amd64/arm64, macOS amd64/arm64, and Windows amd64 archives, `checksums.txt`, and GitHub build provenance attestations. Choose the archive that matches your OS and CPU from [GitHub Releases](https://github.com/capivara-research/MCPEnum/releases).

On Linux amd64, for example:

```sh
curl -fLO https://github.com/capivara-research/MCPEnum/releases/download/v0.2.0/mcpenum_v0.2.0_linux_amd64.tar.gz
curl -fLO https://github.com/capivara-research/MCPEnum/releases/download/v0.2.0/checksums.txt
grep 'mcpenum_v0.2.0_linux_amd64.tar.gz' checksums.txt | sha256sum -c -
gh attestation verify mcpenum_v0.2.0_linux_amd64.tar.gz --repo capivara-research/MCPEnum
tar -xzf mcpenum_v0.2.0_linux_amd64.tar.gz mcpenum
sudo install -m 0755 mcpenum /usr/local/bin/mcpenum
mcpenum --version
```

Replace the version and archive name for another release or platform. On macOS, use `shasum -a 256` to compare the published digest. On Windows, compare with `Get-FileHash -Algorithm SHA256`, extract the ZIP, and place `mcpenum.exe` in a directory on `PATH`. SHA-256 checks integrity against the published checksum; the GitHub attestation additionally binds an archive digest to a workflow and source commit. Neither check proves the program is free of vulnerabilities.

The release workflow is triggered by a stable `vX.Y.Z` tag. It reruns tests and vet, cross-compiles with CGO disabled, archives the binary and license, computes checksums, attests the archives, and publishes the assets. The source build uses the tag for `--version`. Do not move a published tag.
