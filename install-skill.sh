#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

if [ -x "$SCRIPT_DIR/dcg-safe" ]; then
  exec "$SCRIPT_DIR/dcg-safe" internal delegate-install "$@"
fi

VERSION=dev
TAG=$(git -C "$SCRIPT_DIR" describe --tags --exact-match 2>/dev/null || true)
case "$TAG" in
  v[0-9]*.[0-9]*.[0-9]*) VERSION=${TAG#v} ;;
esac

cd "$SCRIPT_DIR"
exec go run \
  -ldflags "-X=github.com/bigbizze/dcg-safe/internal/version.value=$VERSION" \
  ./cmd/dcg-safe internal delegate-install "$@"
