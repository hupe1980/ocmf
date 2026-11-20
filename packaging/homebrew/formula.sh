#!/usr/bin/env bash
# Render the Homebrew formula for a release from its SHA256SUMS.
#
#   packaging/homebrew/formula.sh 0.2.0 SHA256SUMS > Formula/ocmf.rb
set -euo pipefail
version="${1:?usage: formula.sh <version> <SHA256SUMS>}"
sums="${2:?usage: formula.sh <version> <SHA256SUMS>}"
out="$(sed "s/@VERSION@/$version/g" "$(dirname "$0")/ocmf.rb.in")"
for target in aarch64-apple-darwin x86_64-apple-darwin aarch64-unknown-linux-gnu x86_64-unknown-linux-gnu; do
  archive="ocmf-$version-$target.tar.gz"
  sum="$(awk -v a="$archive" '$2 == a || $2 == "*" a { print $1 }' "$sums")"
  if ! [[ "$sum" =~ ^[0-9a-f]{64}$ ]]; then
    echo "formula: no checksum for $archive in $sums" >&2
    exit 1
  fi
  out="${out//@SHA256_$target@/$sum}"
done
if grep -q '@[A-Za-z0-9_-]*@' <<<"$out"; then
  echo "formula: a placeholder was left" >&2
  exit 1
fi
printf '%s\n' "$out"
