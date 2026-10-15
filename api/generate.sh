#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
export GOWORK=off
export GOTOOLCHAIN=go1.26.0
buf=(go run github.com/bufbuild/buf/cmd/buf@v1.57.2)
mode=${1:-generate}
case "$mode" in
  generate|verify) ;;
  *) echo "usage: $0 [generate|verify]" >&2; exit 2 ;;
esac
tmp=$(mktemp -d "${TMPDIR:-/tmp}/litevirt-automation.XXXXXX")
trap 'rm -rf "$tmp"' EXIT
if [[ "$mode" == verify ]]; then
  "${buf[@]}" format --diff --exit-code
  "${buf[@]}" lint
  "${buf[@]}" breaking --against testdata/automation-v1.binpb
fi
"${buf[@]}" generate --output "$tmp/first"
if [[ "$mode" == generate ]]; then
  rm -rf gen
  cp -R "$tmp/first/gen" gen
else
  "${buf[@]}" generate --output "$tmp/second"
  diff -ru "$tmp/first/gen" "$tmp/second/gen"
  diff -ru gen "$tmp/first/gen"
  go test ./... -count=1
fi
