#!/usr/bin/env bash
set -euo pipefail

# Simple release helper
# Usage: ./scripts/release.sh v1.2.3

VERSION=${1:-v1.0.4}

echo "Releasing ${VERSION}..."

if ! command -v gh >/dev/null 2>&1; then
  echo "gh CLI not found; please install GitHub CLI and authenticate."
  exit 1
fi

# Ensure working tree is clean
if [ -n "$(git status --porcelain)" ]; then
  echo "Working tree is not clean. Commit or stash your changes first." >&2
  exit 1
fi

# Push current branch
git push origin HEAD

# Create annotated tag and push
git tag -a "$VERSION" -m "Release $VERSION"
git push origin "$VERSION"

# Create GitHub release
gh release create "$VERSION" --title "$VERSION" --notes "Release $VERSION"

echo "Release $VERSION created." 
