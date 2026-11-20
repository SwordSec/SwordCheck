#!/bin/sh
# Installs the SwordCheck binary from a GitHub release.
#
#   curl -fsSL https://raw.githubusercontent.com/SwordSec/SwordCheck/main/install.sh | sh
#
# The release archive is checked against its published SHA-256 before
# anything is installed. Nothing runs with sudo.
#
# Environment variables:
#   SWORDCHECK_VERSION       release to install, e.g. v0.1.0 (default: the latest)
#   SWORDCHECK_INSTALL_DIR   where to put the binary (default: ~/.local/bin)
#   SWORDCHECK_RELEASES_URL  base URL of the releases, for mirrors and testing
#                            (default: https://github.com/SwordSec/SwordCheck/releases)
set -eu

releases="${SWORDCHECK_RELEASES_URL:-https://github.com/SwordSec/SwordCheck/releases}"
install_dir="${SWORDCHECK_INSTALL_DIR:-${HOME:?HOME is not set}/.local/bin}"

fail() {
    printf 'swordcheck install: %s\n' "$*" >&2
    exit 1
}

[ "$(uname -s)" = Darwin ] || fail "SwordCheck runs on macOS only for now."
for tool in curl shasum tar; do
    command -v "$tool" >/dev/null 2>&1 || fail "$tool is required."
done

# The latest release: GitHub redirects /releases/latest to /releases/tag/<tag>.
version="${SWORDCHECK_VERSION:-}"
if [ -z "$version" ]; then
    latest=$(curl -fsSLI -o /dev/null -w '%{url_effective}' "$releases/latest") ||
        fail "could not reach $releases."
    version="${latest##*/}"
fi
case "$version" in
v[0-9]*) ;;
*)
    [ -z "${SWORDCHECK_VERSION:-}" ] ||
        fail "'$version' is not a release tag; use one such as v0.1.0."
    fail "there is no published release yet; build from source instead (see the README)."
    ;;
esac

archive="swordcheck-$version-macos-universal.tar.gz"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
trap 'exit 1' HUP INT TERM

printf 'Downloading SwordCheck %s...\n' "$version"
curl -fsSL -o "$tmp/$archive" "$releases/download/$version/$archive" ||
    fail "could not download $archive."
curl -fsSL -o "$tmp/$archive.sha256" "$releases/download/$version/$archive.sha256" ||
    fail "could not download $archive.sha256."

# The .sha256 file names the archive, so check it from the download folder.
(cd "$tmp" && shasum -a 256 -c "$archive.sha256" >/dev/null 2>&1) ||
    fail "checksum mismatch for $archive: the download is corrupt or was tampered with."

mkdir "$tmp/unpacked"
tar -xzf "$tmp/$archive" -C "$tmp/unpacked"
[ -f "$tmp/unpacked/swordcheck" ] || fail "$archive does not contain the swordcheck binary."

# Copy next to the target and rename, so a running copy is never half-written.
mkdir -p "$install_dir"
cp "$tmp/unpacked/swordcheck" "$install_dir/.swordcheck.new"
chmod 0755 "$install_dir/.swordcheck.new"
mv -f "$install_dir/.swordcheck.new" "$install_dir/swordcheck"

installed=$("$install_dir/swordcheck" --version) || fail "the installed binary does not run."
printf 'Installed %s to %s/swordcheck\n' "$installed" "$install_dir"

case ":$PATH:" in
*":$install_dir:"*) ;;
*)
    printf '\n%s is not in your PATH. Add it with:\n' "$install_dir"
    printf '  echo '\''export PATH="%s:$PATH"'\'' >> ~/.zshrc && exec zsh\n' "$install_dir"
    ;;
esac
