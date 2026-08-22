#!/usr/bin/env bash
set -euo pipefail

TAG="v3.0.3"
EXPECTED_VERSION="3.0.3"
WORKFLOW=".github/workflows/release-v3.0.3.yml"
MODE="${1:-}"

if [[ "$MODE" != "--check-only" && "$MODE" != "--push" ]]; then
  echo "usage: $0 --check-only|--push" >&2
  exit 64
fi

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"
branch="$(git branch --show-current)"
if [[ "$branch" != "main" ]]; then
  echo "refusing tag operation: current branch must be main (got: ${branch:-detached})" >&2
  exit 1
fi
if ! git diff --quiet || ! git diff --cached --quiet; then
  echo "refusing tag operation: working tree/index must be clean" >&2
  exit 1
fi
if [[ ! -f "$WORKFLOW" ]]; then
  echo "refusing tag operation: publication workflow is missing" >&2
  exit 1
fi
if [[ "$(tr -d '\r\n' < VERSION)" != "$EXPECTED_VERSION" ]]; then
  echo "refusing tag operation: VERSION is not $EXPECTED_VERSION" >&2
  exit 1
fi

git fetch origin main --tags
local_sha="$(git rev-parse HEAD)"
remote_main_sha="$(git rev-parse origin/main)"
if [[ "$local_sha" != "$remote_main_sha" ]]; then
  echo "refusing tag operation: local main is not exactly origin/main" >&2
  exit 1
fi
if ! grep -Fq 'test "$GITHUB_SHA" = "$main_sha"' "$WORKFLOW"; then
  echo "refusing tag operation: publication workflow lacks exact-main SHA guard" >&2
  exit 1
fi
if git show-ref --verify --quiet "refs/tags/$TAG"; then
  echo "refusing tag operation: local tag $TAG already exists" >&2
  exit 1
fi
set +e
git ls-remote --exit-code --tags origin "refs/tags/$TAG" >/dev/null 2>&1
remote_tag_status=$?
set -e
if [[ "$remote_tag_status" -eq 0 ]]; then
  echo "refusing tag operation: remote tag $TAG already exists" >&2
  exit 1
elif [[ "$remote_tag_status" -ne 2 ]]; then
  echo "refusing tag operation: could not determine remote tag state" >&2
  exit 1
fi

printf 'tag target validated: %s -> %s\n' "$TAG" "$local_sha"
if [[ "$MODE" == "--check-only" ]]; then
  echo "check-only: PASS (no tag created)"
  exit 0
fi

git tag -a "$TAG" "$local_sha" -m "OmniGuard V2X $TAG"
if ! git push origin "refs/tags/$TAG"; then
  git tag -d "$TAG" >/dev/null 2>&1 || true
  echo "tag push failed; local tag removed" >&2
  exit 1
fi

echo "tag push: PASS ($TAG -> $local_sha)"
