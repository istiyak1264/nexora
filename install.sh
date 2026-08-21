#!/usr/bin/env bash
go build -trimpath -ldflags='-s -w' -o nexora ./cmd/nexora
set -euo pipefail

PREFIX="${PREFIX:-/usr/local}"
SYSCONFDIR="${SYSCONFDIR:-/etc/nexora}"
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"

if [[ ! -f "$SCRIPT_DIR/nexora-linux-amd64" && ! -f "$SCRIPT_DIR/nexora" ]]; then
  echo "error: nexora binary not found beside install.sh" >&2
  exit 1
fi

binary="$SCRIPT_DIR/nexora-linux-amd64"
[[ -f "$binary" ]] || binary="$SCRIPT_DIR/nexora"

install -Dm0755 "$binary" "$PREFIX/bin/nexora"
install -d "$SYSCONFDIR"
if [[ -f "$SCRIPT_DIR/provider-config.yml" ]]; then
  install -Dm0644 "$SCRIPT_DIR/provider-config.yml" "$SYSCONFDIR/provider-config.yml"
fi

echo "Installed: $PREFIX/bin/nexora"
if [[ -f "$SYSCONFDIR/provider-config.yml" ]]; then
  echo "Configuration: $SYSCONFDIR/provider-config.yml"
fi
echo "Run: nexora --version"
