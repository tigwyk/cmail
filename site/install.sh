#!/bin/sh
# cmail installer for Linux/macOS.
#
#   curl -fsSL https://tigwyk.github.io/cmail/install.sh | sh
#
# Options (env vars): VERSION=x.y.z, INSTALL_DIR=~/somewhere
#
# Verifies the SHA-256 of the downloaded archive against the release's
# SHA256SUMS.txt before installing anything. No root required: installs to
# ~/.cmail/bin by default and suggests a PATH line if needed.
# Uninstall = delete the install dir.

set -eu

repo="tigwyk/cmail"
VERSION="${VERSION:-}"
INSTALL_DIR="${INSTALL_DIR:-$HOME/.cmail/bin}"

fail() { echo "install failed: $*" >&2; exit 1; }

os=$(uname -s); arch=$(uname -m)
case "$os:$arch" in
    Linux:x86_64)  target="x86_64-unknown-linux-gnu" ;;
    Linux:aarch64) target="aarch64-unknown-linux-gnu" ;;
    Darwin:x86_64) target="x86_64-apple-darwin" ;;
    Darwin:arm64)  target="aarch64-apple-darwin" ;;
    *) fail "no release for $os $arch" ;;
esac

if [ -z "$VERSION" ]; then
    echo "resolving latest release..."
    VERSION=$(curl -fsSL "https://api.github.com/repos/$repo/releases/latest" \
        | sed -n 's/.*"tag_name": *"\(v[^"]*\)".*/\1/p' | tr -d 'v')
    [ -n "$VERSION" ] || fail "could not query latest release"
fi
echo "installing cmail v$VERSION"

archive="cmail-v$VERSION-$target.tar.gz"
base="https://github.com/$repo/releases/download/v$VERSION"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

echo "downloading $archive ..."
curl -fsSL -o "$tmp/$archive" "$base/$archive" || fail "download failed"
curl -fsSL -o "$tmp/SHA256SUMS.txt" "$base/SHA256SUMS.txt" || fail "could not download SHA256SUMS.txt"

echo "verifying sha256 ..."
expected=$(awk -v f="$archive" '$2 == f || $2 == "*"f {print $1}' "$tmp/SHA256SUMS.txt")
[ -n "$expected" ] || fail "SHA256SUMS.txt has no entry for $archive"
if command -v sha256sum >/dev/null 2>&1; then hash_cmd="sha256sum"
elif command -v shasum >/dev/null 2>&1; then hash_cmd="shasum -a 256"
else fail "need sha256sum or shasum to verify"; fi
actual=$($hash_cmd "$tmp/$archive" | awk '{print $1}')
[ "$actual" = "$expected" ] || fail "sha256 mismatch (expected $expected, got $actual)"
echo "sha256 ok"

mkdir -p "$INSTALL_DIR"
tar -xzf "$tmp/$archive" -C "$tmp"
cp "$tmp/cmail-v$VERSION-$target/cmail" "$INSTALL_DIR/" 2>/dev/null \
    || cp "$(find "$tmp" -name cmail -type f | head -n1)" "$INSTALL_DIR/"
[ -f "$INSTALL_DIR/cmail-relayd" ] || cp "$(find "$tmp" -name cmail-relayd -type f | head -n1)" "$INSTALL_DIR/" 2>/dev/null || true
chmod +x "$INSTALL_DIR"/*
echo "installed to $INSTALL_DIR"

case ":$PATH:" in
    *":$INSTALL_DIR:"*) ;;
    *)
        line='export PATH="$HOME/.cmail/bin:$PATH"'
        rc=""
        for f in "$HOME/.zshrc" "$HOME/.bashrc" "$HOME/.profile"; do
            [ -f "$f" ] && rc="$f" && break
        done
        if [ -n "$rc" ] && ! grep -qF '.cmail/bin' "$rc"; then
            printf '\n# cmail\n%s\n' "$line" >> "$rc"
            echo "added PATH line to $rc"
        elif [ -n "$rc" ]; then
            echo "PATH line already present in $rc"
        else
            echo "NOTE: add this to your shell rc: $line"
        fi
        ;;
esac

echo
echo "done. open a NEW shell (or re-source your rc), then:"
echo "  cmail --version"
echo "  cmail init --name <your-agent>"
