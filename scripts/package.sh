#!/usr/bin/env bash
# Builds the self-contained installer for this machine's OS and CPU:
#   dist/vpn-installer-<version>-<os>-<arch>  (+ .sha256)
# It carries vpnd (with the web UI) and vpnctl; run it with install, upgrade, uninstall or status.
# The licences of the third-party software in the programs travel with it: inside the installer
# (`vpn-installer licenses`) and as dist/<name>.notices.txt (scripts/third_party_notices.py).
# Build on the target platform: macOS for macOS, Linux for Linux.
set -euo pipefail
cd "$(dirname "$0")/.."

# Every crate of Cargo.lock, also the ones no program compiles: the notices are written from
# `cargo metadata --offline`, which reads the manifest of each of them.
cargo fetch --locked
(cd web && pnpm install --frozen-lockfile && pnpm build)
cargo build --release --locked -p vpnd -p vpnctl
python3 -I scripts/third_party_notices.py target/release/THIRD-PARTY-NOTICES.txt >&2
VPN_INSTALLER_PAYLOAD="${PWD}/target/release" cargo build --release --locked -p vpn-installer

version=$(cargo pkgid -p vpn-installer | sed 's/.*[#@]//')
os=$(uname -s | tr '[:upper:]' '[:lower:]')
arch=$(uname -m)
name="vpn-installer-${version}-${os}-${arch}"
mkdir -p dist
cp target/release/vpn-installer "dist/${name}"
cp target/release/THIRD-PARTY-NOTICES.txt "dist/${name}.notices.txt"
if command -v sha256sum >/dev/null; then
  (cd dist && sha256sum "${name}" > "${name}.sha256")
else
  (cd dist && shasum -a 256 "${name}" > "${name}.sha256")
fi
echo "dist/${name}"
