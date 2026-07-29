#!/bin/sh

set -eu

repository_root=$(git rev-parse --show-toplevel)
version=$(node -p "require('$repository_root/package.json').version")
destination=${1:-"$repository_root/outputs/Mayak-$version-source.zip"}

mkdir -p "$(dirname "$destination")"
git -C "$repository_root" archive \
  --format=zip \
  --prefix="Mayak-$version/" \
  --output="$destination" \
  HEAD

printf '%s\n' "Created $destination from tracked files at HEAD."
