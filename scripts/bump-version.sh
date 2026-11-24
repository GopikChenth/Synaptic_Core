#!/usr/bin/env bash
# ==============================================================================
# bump-version.sh <new-version>
#
# Sets the crate version (Cargo.toml + Cargo.lock), commits, and creates the
# matching annotated tag. Push with:  git push origin main --follow-tags
# The release pipeline refuses tags that don't match Cargo.toml, so always
# release through this script.
# ==============================================================================
set -euo pipefail

NEW="${1:?usage: bump-version.sh <new-version>   e.g. 1.1.0 or 1.2.0-beta.1}"
NEW="${NEW#v}"
[[ "${NEW}" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]] || { echo "error: '${NEW}' is not semver" >&2; exit 2; }

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

[[ -z "$(git status --porcelain)" ]] || { echo "error: working tree is not clean" >&2; exit 1; }
git rev-parse -q --verify "refs/tags/v${NEW}" >/dev/null && { echo "error: tag v${NEW} already exists" >&2; exit 1; }

OLD="$(sed -n '/^\[package\]/,/^\[/{s/^version *= *"\(.*\)"/\1/p}' Cargo.toml | head -1)"
echo "Bumping ${OLD} -> ${NEW}"

# Only the [package] version line, never dependency versions.
awk -v new="${NEW}" '
    /^\[package\]/ { in_pkg = 1 }
    /^\[/ && !/^\[package\]/ { in_pkg = 0 }
    in_pkg && /^version *=/ && !done { print "version = \"" new "\""; done = 1; next }
    { print }
' Cargo.toml > Cargo.toml.tmp && mv Cargo.toml.tmp Cargo.toml

cargo update -p synapse-core --offline >/dev/null 2>&1 || cargo update -p synapse-core >/dev/null
cargo metadata --no-deps --format-version 1 >/dev/null

git add Cargo.toml Cargo.lock
git commit -q -m "chore(release): v${NEW}"
git tag -a "v${NEW}" -m "synapse-core v${NEW}"
echo "Created commit and tag v${NEW}. Publish with:"
echo "  git push origin HEAD --follow-tags"
