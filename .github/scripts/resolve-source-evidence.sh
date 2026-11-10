#!/usr/bin/env bash
set -euo pipefail

: "${TARGET_REPOSITORY:?TARGET_REPOSITORY is required}"
: "${HEAD_SHA:?HEAD_SHA is required}"
: "${RUNNER_TEMP:?RUNNER_TEMP is required}"
: "${GITHUB_OUTPUT:?GITHUB_OUTPUT is required}"

run_id="${SOURCE_RUN_ID:-}"
source_url="${SOURCE_CI_URL:-}"
status_file="$RUNNER_TEMP/source-evidence-status.txt"
mkdir -p "$RUNNER_TEMP/source-artifacts"
{
  echo "target_repository=$TARGET_REPOSITORY"
  echo "head_sha=$HEAD_SHA"
  echo "requested_source_run_id=${run_id:-none}"
  echo "requested_source_ci_url=${source_url:-none}"
} > "$status_file"

evidence_failure() {
  local reason="$1"
  echo "status=failure" >> "$status_file"
  echo "reason=$reason" >> "$status_file"
  echo "available=false" >> "$GITHUB_OUTPUT"
}

if [ -n "$source_url" ] && [[ "$source_url" != https://prow.k8s.io/view/gs/* ]]; then
  evidence_failure "source_ci_url is not a supported Prow GS URL"
  exit 0
fi

if [ -z "$run_id" ] && [ -z "$source_url" ]; then
  run_id="$(gh run list --repo "$TARGET_REPOSITORY" --commit "$HEAD_SHA" \
    --status failure --limit 1 --json databaseId --jq '.[0].databaseId // empty')"
fi
if [ -z "$run_id" ] && [ -z "$source_url" ]; then
  source_url="$(gh api --paginate "repos/$TARGET_REPOSITORY/commits/$HEAD_SHA/status" \
    --jq '.statuses[] | select(.state == "failure") | .target_url' \
    | grep '^https://prow.k8s.io/view/gs/' | sed -n '1p' || true)"
fi

if [ -z "$run_id" ]; then
  if [[ "$source_url" != https://prow.k8s.io/view/gs/* ]]; then
    evidence_failure "No failed source CI run or supported Prow status context found for $TARGET_REPOSITORY@$HEAD_SHA"
    exit 0
  fi
  source_url="${source_url%/}"
  build_id="${source_url##*/}"
  log_url="https://storage.googleapis.com/${source_url#https://prow.k8s.io/view/gs/}/build-log.txt"
  {
    echo "provider=prow"
    echo "source_url=$source_url"
    echo "build_id=$build_id"
    echo "log_url=$log_url"
  } >> "$status_file"
  if ! curl --fail --silent --show-error --location "$log_url" > "$RUNNER_TEMP/source-ci.log"; then
    evidence_failure "Could not read Prow log: $log_url"
    exit 0
  fi
  source_provider="prow"
else
  if ! gh run view "$run_id" --repo "$TARGET_REPOSITORY" --log-failed \
    > "$RUNNER_TEMP/source-ci.log"; then
    evidence_failure "Could not read failed-job log for source CI run $run_id"
    exit 0
  fi
  gh run download "$run_id" --repo "$TARGET_REPOSITORY" \
    --dir "$RUNNER_TEMP/source-artifacts" || echo "artifact_download=failed" >> "$status_file"
  {
    echo "provider=github-actions"
    echo "run_id=$run_id"
    echo "log_path=$RUNNER_TEMP/source-ci.log"
    echo "artifact_dir=$RUNNER_TEMP/source-artifacts"
  } >> "$status_file"
  source_provider="github-actions"
fi

if [ -z "$run_id" ] && [ -z "$source_url" ]; then
  evidence_failure "No failed source CI run found for $TARGET_REPOSITORY@$HEAD_SHA"
  exit 0
fi
if [ ! -s "$RUNNER_TEMP/source-ci.log" ]; then
  evidence_failure "Source CI evidence was empty"
  exit 0
fi

sed -E \
  -e 's/(authorization:[[:space:]]*bearer[[:space:]]+)[^[:space:]]+/\1[REDACTED]/Ig' \
  -e 's/((token|password|secret|api[_-]?key)[=:][[:space:]]*)[^[:space:]]+/\1[REDACTED]/Ig' \
  -e 's/(gh[pousr]_[A-Za-z0-9_]+|github_pat_[A-Za-z0-9_]+|AKIA[0-9A-Z]{16})/[REDACTED]/g' \
  "$RUNNER_TEMP/source-ci.log" > "$RUNNER_TEMP/source-ci-sanitized.log"
{
  head -c 131072 "$RUNNER_TEMP/source-ci-sanitized.log"
  printf '\n[... CI evidence middle omitted ...]\n'
  tail -c 131072 "$RUNNER_TEMP/source-ci-sanitized.log"
} > "$RUNNER_TEMP/source-ci-bounded.log"

echo "source_url=$source_url" >> "$GITHUB_OUTPUT"
echo "provider=$source_provider" >> "$GITHUB_OUTPUT"
echo "run_id=$run_id" >> "$GITHUB_OUTPUT"
echo "build_id=${build_id:-}" >> "$GITHUB_OUTPUT"
echo "log_path=$RUNNER_TEMP/source-ci.log" >> "$GITHUB_OUTPUT"
echo "bounded_log_path=$RUNNER_TEMP/source-ci-bounded.log" >> "$GITHUB_OUTPUT"
echo "artifact_dir=$RUNNER_TEMP/source-artifacts" >> "$GITHUB_OUTPUT"
echo "status=success" >> "$status_file"
echo "available=true" >> "$GITHUB_OUTPUT"
