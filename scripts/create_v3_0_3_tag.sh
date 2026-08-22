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
for required_workflow in \
  .github/workflows/security-baseline.yml \
  .github/workflows/pkcs11-source-conformance.yml \
  .github/workflows/windows-runtime-smoke.yml; do
  if [[ ! -f "$required_workflow" ]]; then
    echo "refusing tag operation: required final gate workflow is missing: $required_workflow" >&2
    exit 1
  fi
done
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

if ! command -v gh >/dev/null 2>&1; then
  echo "refusing tag operation: GitHub CLI (gh) is required to verify exact-main release gates" >&2
  exit 1
fi
if ! gh auth status >/dev/null 2>&1; then
  echo "refusing tag operation: GitHub CLI is not authenticated" >&2
  exit 1
fi

repo_slug="$(gh repo view --json nameWithOwner --jq .nameWithOwner)"
for workflow in "Security Baseline" "PKCS11 Source Conformance" "Windows Runtime Smoke"; do
  runs_json="$(gh run list --repo "$repo_slug" --workflow "$workflow" --branch main --event push --limit 30 --json headSha,status,conclusion,url)"
  RUNS_JSON="$runs_json" python3 - "$local_sha" "$workflow" <<'PY'
import json
import os
import sys

target = sys.argv[1]
workflow = sys.argv[2]
runs = json.loads(os.environ["RUNS_JSON"])
matches = [run for run in runs if run.get("headSha") == target]
if not matches:
    raise SystemExit(f"no {workflow} push run found for exact current main commit")
run = matches[0]
if run.get("status") != "completed" or run.get("conclusion") != "success":
    raise SystemExit(f"{workflow} for exact current main commit is not completed successfully")
print(f"exact-main {workflow}: PASS {run.get('url', '')}")
PY
done

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
if gh release view "$TAG" --repo "$repo_slug" >/dev/null 2>&1; then
  echo "refusing tag operation: GitHub Release $TAG already exists" >&2
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
