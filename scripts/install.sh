#!/bin/sh
# Installs VPN Manager for the current user from a published release, in one line:
#
#   curl -fsSL https://raw.githubusercontent.com/DennySORA/vpn-manager/main/scripts/install.sh | sh
#
# Options go after `sh -s --`:
#
#   ... | sh -s -- --version 0.1.0          a given release instead of the latest
#   ... | sh -s -- --port 18765             anything else is passed to `vpn-installer install`
#
# What it does: finds this machine's installer in the release (vpn-installer-<version>-<os>-<arch>,
# built by .github/workflows/release.yml with scripts/package.sh), downloads it and its SHA-256
# over HTTPS, refuses a file that does not match, and runs `vpn-installer install`. The installer
# sets VPN Manager up for this user only, as a systemd user service (Linux) or a launchd
# LaunchAgent (macOS); nothing here asks for root. Running it again upgrades.
#
# Environment: VPN_MANAGER_REPO_URL replaces https://github.com/DennySORA/vpn-manager (a fork or
# a mirror with the same release layout).
set -eu

REPO_URL=${VPN_MANAGER_REPO_URL:-https://github.com/DennySORA/vpn-manager}

say() {
  printf '%s\n' "$*"
}

die() {
  printf 'install.sh: %s\n' "$*" >&2
  exit 1
}

usage() {
  cat <<'USAGE'
Installs VPN Manager for the current user from a published release.

  install.sh [--version X.Y.Z] [options of `vpn-installer install`]

  --version X.Y.Z   install that release instead of the latest one
  --port N, --listen-address ADDR, --allow-client CIDR, --root DIR, ...
                    passed on to `vpn-installer install`

Afterwards the installer keeps a copy of itself in the installation's bin/ directory:
`vpn-installer status`, `vpn-installer upgrade` and `vpn-installer uninstall [--purge]`.
USAGE
}

# fetch URL FILE WHAT: download over HTTPS only, following redirects; an HTTP error ends the
# installation and says WHAT is missing.
fetch() {
  if command -v curl >/dev/null 2>&1; then
    curl --proto '=https' --tlsv1.2 --fail --silent --show-error --location --output "$2" "$1" || die "$3"
  elif command -v wget >/dev/null 2>&1; then
    wget --https-only --quiet --output-document="$2" "$1" || die "$3"
  else
    die "curl or wget is needed to download the installer"
  fi
}

# The tag the release page's "latest" link leads to, without its leading v.
latest_version() {
  if command -v curl >/dev/null 2>&1; then
    target=$(curl --proto '=https' --tlsv1.2 --fail --silent --show-error --location --head \
      --output /dev/null --write-out '%{url_effective}' "${REPO_URL}/releases/latest") ||
      die "cannot reach ${REPO_URL}/releases"
  elif command -v wget >/dev/null 2>&1; then
    target=$(wget --https-only --quiet --server-response --spider "${REPO_URL}/releases/latest" 2>&1 |
      sed -n 's/^ *[Ll]ocation: *//p' | tail -n 1 | tr -d '\r')
  else
    die "curl or wget is needed to download the installer"
  fi
  case "${target}" in
    */releases/tag/v[0-9]*) say "${target##*/releases/tag/v}" ;;
    *) die "no published release found at ${REPO_URL}/releases" ;;
  esac
}

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d ' ' -f 1
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | cut -d ' ' -f 1
  else
    die "sha256sum or shasum is needed to check the download"
  fi
}

main() {
  version=${VPN_MANAGER_VERSION:-}
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --version)
        [ "$#" -ge 2 ] || die "--version needs a value, for example --version 0.1.0"
        version=$2
        shift 2
        ;;
      -h | --help)
        usage
        exit 0
        ;;
      *) break ;;
    esac
  done

  os=$(uname -s | tr '[:upper:]' '[:lower:]')
  arch=$(uname -m)
  case "${os}" in
    linux | darwin) ;;
    *) die "VPN Manager runs on Linux and macOS; this is ${os}" ;;
  esac

  if [ -z "${version}" ]; then
    version=$(latest_version)
  fi
  version=${version#v}
  case "${version}" in
    '' | *[!0-9A-Za-z.+-]*) die "not a version: ${version}" ;;
    *) ;;
  esac

  name="vpn-installer-${version}-${os}-${arch}"
  url="${REPO_URL}/releases/download/v${version}/${name}"
  work=$(mktemp -d)
  trap 'rm -rf "${work}"' EXIT INT TERM

  say "VPN Manager ${version} for ${os} ${arch}"
  say "  downloading ${url}"
  fetch "${url}" "${work}/${name}" \
    "cannot download ${name}: release v${version} may have no installer for ${os} ${arch} (scripts/package.sh builds one from source)"
  fetch "${url}.sha256" "${work}/${name}.sha256" "cannot download the checksum of ${name}"

  expected=$(cut -d ' ' -f 1 "${work}/${name}.sha256")
  actual=$(sha256_of "${work}/${name}")
  case "${expected}" in
    '' | *[!0-9a-f]*) die "the published checksum of ${name} is not a SHA-256" ;;
    *) ;;
  esac
  [ "${#expected}" -eq 64 ] || die "the published checksum of ${name} is not a SHA-256"
  [ "${expected}" = "${actual}" ] ||
    die "checksum mismatch for ${name}: published ${expected}, downloaded ${actual}; nothing was installed"
  say "  SHA-256 ${actual} matches the release"

  chmod 700 "${work}/${name}"
  "${work}/${name}" install "$@"
}

main "$@"
