#!/usr/bin/env bash
set -euo pipefail

# Release script for ghenv
# Creates a release on the develop branch, tags it, and merges to main.
#
# Usage: ./scripts/release.sh [major|minor|patch]
# Default: patch

BUMP_TYPE="${1:-patch}"
PYPROJECT="pyproject.toml"

# --- Validation ---

if [[ ! -f "$PYPROJECT" ]]; then
    echo "ERROR: $PYPROJECT not found. Run from the repo root." >&2
    exit 1
fi

CURRENT_BRANCH=$(git branch --show-current)
if [[ "$CURRENT_BRANCH" != "develop" ]]; then
    echo "ERROR: Must be on the develop branch. Currently on '$CURRENT_BRANCH'." >&2
    exit 1
fi

if [[ -n "$(git status --porcelain)" ]]; then
    echo "ERROR: Working tree is not clean. Commit or stash changes first." >&2
    exit 1
fi

if [[ "$BUMP_TYPE" != "major" && "$BUMP_TYPE" != "minor" && "$BUMP_TYPE" != "patch" ]]; then
    echo "ERROR: Invalid bump type '$BUMP_TYPE'. Use: major, minor, or patch." >&2
    exit 1
fi

# --- Read current version ---

CURRENT_VERSION=$(grep -Po '(?<=^version = ")[^"]+' "$PYPROJECT")
if [[ -z "$CURRENT_VERSION" ]]; then
    echo "ERROR: Could not read version from $PYPROJECT." >&2
    exit 1
fi

IFS='.' read -r MAJOR MINOR PATCH <<< "$CURRENT_VERSION"

# --- Compute new version ---

case "$BUMP_TYPE" in
    major) MAJOR=$((MAJOR + 1)); MINOR=0; PATCH=0 ;;
    minor) MINOR=$((MINOR + 1)); PATCH=0 ;;
    patch) PATCH=$((PATCH + 1)) ;;
esac

NEW_VERSION="${MAJOR}.${MINOR}.${PATCH}"
TAG="v${NEW_VERSION}"

echo "Releasing: $CURRENT_VERSION -> $NEW_VERSION ($BUMP_TYPE)"

# Check tag doesn't already exist
if git rev-parse "$TAG" >/dev/null 2>&1; then
    echo "ERROR: Tag '$TAG' already exists." >&2
    exit 1
fi

# --- Bump version in pyproject.toml ---

sed -i "s/^version = \"${CURRENT_VERSION}\"/version = \"${NEW_VERSION}\"/" "$PYPROJECT"
echo "Updated $PYPROJECT version to $NEW_VERSION"

# --- Commit, tag, merge ---

git add "$PYPROJECT"
git commit -m "release: v${NEW_VERSION}"
git tag -a "$TAG" -m "Release ${TAG}"
echo "Created commit and tag $TAG on develop"

git checkout main
git merge develop --no-edit
echo "Merged develop into main"

git checkout develop
echo ""
echo "Release $TAG complete."
echo ""
echo "To push:"
echo "  git push origin develop main $TAG"
