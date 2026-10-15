#!/usr/bin/env bash
set -Eeuo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
TMP_DIR=$(mktemp -d)

export PATH="$ROOT/tests/bin:$PATH"
export FIXTURE_DIR="$ROOT/tests/fixtures"
export HAWK_BASE_URL='https://hawk.example'
export HAWK_BUILDBOX_TOKEN='contract-token'
export BUILDBOX_STATE_DIR="$TMP_DIR/state"
export CURL_LOG="$TMP_DIR/curl.log"
export FLUTTER_LOG="$TMP_DIR/flutter.log"
export GITHUB_WORKSPACE="$TMP_DIR/workspace"
export GITHUB_OUTPUT="$TMP_DIR/github-output.log"
export GITHUB_ENV="$TMP_DIR/github-env.log"
export BUILDBOX_GITHUB_RUN_ID=987654321
printf '%s\n' 'UNCHANGED=1' >"$GITHUB_ENV"

mkdir -p "$GITHUB_WORKSPACE/aviary-source/.git"
mkdir -p "$GITHUB_WORKSPACE/aviary-source/waterfowl/apps/swan"
mkdir -p "$BUILDBOX_STATE_DIR"

assert_file_contains() {
  local file=$1
  local expected=$2
  if ! grep -F -- "$expected" "$file" >/dev/null; then
    printf 'expected %s to contain %s\n' "$file" "$expected" >&2
    exit 1
  fi
}

assert_file_not_contains() {
  local file=$1
  local unexpected=$2
  if grep -F -- "$unexpected" "$file" >/dev/null; then
    printf 'expected %s not to contain %s\n' "$file" "$unexpected" >&2
    exit 1
  fi
}

COMPILE_JOB=$(sed -n '/^  compile:/,/^  sign:/p' "$ROOT/.github/workflows/build.yml")
if [[ -z "$COMPILE_JOB" ]]; then
  COMPILE_JOB=$(sed -n '/^  build:/,/^  finalize:/p' "$ROOT/.github/workflows/build.yml")
fi
if grep -F 'HAWK_BUILDBOX_TOKEN' <<<"$COMPILE_JOB" >/dev/null; then
  printf 'compile job must not receive the Hawk service token\n' >&2
  exit 1
fi
if grep -F 'build-input-' <<<"$COMPILE_JOB" >/dev/null; then
  printf 'compile job must not download the full prepare artifact\n' >&2
  exit 1
fi
if ! grep -F 'compile-input-' <<<"$COMPILE_JOB" >/dev/null; then
  printf 'compile job must restore the compile input slice\n' >&2
  exit 1
fi
PREPARE_JOB=$(sed -n '/^  prepare:/,/^  compile:/p' "$ROOT/.github/workflows/build.yml")
if ! grep -F "github.event_name == 'workflow_dispatch'" <<<"$PREPARE_JOB" >/dev/null; then
  printf 'prepare must skip the push event GitHub sends when the workflow file changes\n' >&2
  exit 1
fi
SIGN_JOB=$(sed -n '/^  sign:/,/^  finalize:/p' "$ROOT/.github/workflows/build.yml")
FINALIZE_JOB=$(sed -n '/^  finalize:/,$p' "$ROOT/.github/workflows/build.yml")
if ! grep -F 'public repository cannot carry unsigned build artifacts' <<<"$PREPARE_JOB" >/dev/null; then
  printf 'prepare must fail closed on a public repository\n' >&2
  exit 1
fi
prepare_public=$(grep -n -F 'public repository cannot carry unsigned build artifacts' <<<"$PREPARE_JOB" | head -n 1 | cut -d: -f1)
prepare_running=$(grep -n -F 'scripts/report-result running' <<<"$PREPARE_JOB" | head -n 1 | cut -d: -f1)
prepare_failed=$(grep -n -F 'scripts/report-result failed' <<<"$PREPARE_JOB" | head -n 1 | cut -d: -f1)
if [[ -z "$prepare_public" || -z "$prepare_running" || -z "$prepare_failed" ]]; then
  printf 'prepare must reject a public repository, report running, and report failed\n' >&2
  exit 1
fi
if [[ "$prepare_public" -ge "$prepare_running" || "$prepare_running" -ge "$prepare_failed" ]]; then
  printf 'prepare must reject a public repository before reporting running, and report failed only after that\n' >&2
  exit 1
fi
if ! grep -F 'if: failure()' <<<"$PREPARE_JOB" >/dev/null; then
  printf 'prepare must report failed when an earlier prepare step fails\n' >&2
  exit 1
fi
if ! grep -F "needs.prepare.result == 'success'" <<<"$FINALIZE_JOB" >/dev/null; then
  printf 'finalize must stay gated on prepare success so it does not send a second callback\n' >&2
  exit 1
fi
if grep -F 'build-input-' <<<"$SIGN_JOB" >/dev/null; then
  printf 'sign job must not download the full prepare artifact\n' >&2
  exit 1
fi
if ! grep -F 'needs.sign.result == '"'"'success'"'" <<<"$FINALIZE_JOB" >/dev/null; then
  printf 'finalize success path must require the sign job\n' >&2
  exit 1
fi

export MOCK_GIT_HEAD='1111111111111111111111111111111111111111'
"$ROOT/scripts/load-build-spec" 101:401
"$ROOT/scripts/report-result" running
"$ROOT/scripts/export-job-inputs" compile "$TMP_DIR/compile-input"
if [[ -e "$TMP_DIR/compile-input/uploads.json" || -e "$TMP_DIR/compile-input/spec-response.json" ]]; then
  printf 'compile input must not include upload authorization\n' >&2
  exit 1
fi
if jq -e 'has("uploads") or has("callbackUrl")' "$TMP_DIR/compile-input/spec.json" >/dev/null; then
  printf 'compile spec must not include upload authorization\n' >&2
  exit 1
fi
"$ROOT/scripts/export-job-inputs" sign "$TMP_DIR/sign-input"
if [[ -e "$TMP_DIR/sign-input/uploads.json" || -e "$TMP_DIR/sign-input/spec.json" || -e "$TMP_DIR/sign-input/spec-response.json" ]]; then
  printf 'sign input must only contain target identity\n' >&2
  exit 1
fi

# Later jobs see only the exported slice, not the prepare state that holds URLs.
PREPARE_STATE=$BUILDBOX_STATE_DIR
BUILDBOX_STATE_DIR="$TMP_DIR/compile-state"
export BUILDBOX_STATE_DIR
mkdir -p "$BUILDBOX_STATE_DIR"
cp -a "$TMP_DIR/compile-input/." "$BUILDBOX_STATE_DIR/"
"$ROOT/scripts/build-android"
assert_file_contains "$FLUTTER_LOG" "SWAN_ARTIFACT_KIND=unsigned_release"
if "$ROOT/scripts/sign-android" 2>"$TMP_DIR/unsigned.err"; then
  printf 'expected unsigned artifacts without signing material to fail\n' >&2
  exit 1
fi
assert_file_contains "$TMP_DIR/unsigned.err" "signing material is not configured"
if [[ -e "$BUILDBOX_STATE_DIR/artifacts.json" || -e "$BUILDBOX_STATE_DIR/sign-proof.json" ]]; then
  printf 'failed signing must not write a success proof\n' >&2
  exit 1
fi
"$ROOT/scripts/report-result" failed "signing material is not configured"
jq -e '
  .status == "failed" and
  .errorCode == "BUILD_FAILED" and
  .errorMessage == "signing material is not configured" and
  .artifacts == []
' "$BUILDBOX_STATE_DIR/callback-failed.json" >/dev/null

MATERIAL_DIR="$TMP_DIR/material"
mkdir -p "$MATERIAL_DIR"
export BUILDBOX_SIGNING_MATERIAL_DIR="$MATERIAL_DIR"
if "$ROOT/scripts/sign-android" 2>"$TMP_DIR/material.err"; then
  printf 'expected present signing material to fail closed in phase A\n' >&2
  exit 1
fi
assert_file_contains "$TMP_DIR/material.err" "production signing is not implemented"
unset BUILDBOX_SIGNING_MATERIAL_DIR

# Debug and already-signed compile outputs are refused before any copy.
FLUTTER_OUTPUT_KIND=debug
export FLUTTER_OUTPUT_KIND
: >"$FLUTTER_LOG"
if "$ROOT/scripts/build-android" 2>"$TMP_DIR/debug.err"; then
  printf 'expected debug-signed compile output to fail\n' >&2
  exit 1
fi
assert_file_contains "$TMP_DIR/debug.err" "refusing debug-signed compile output"
FLUTTER_OUTPUT_KIND=signed
if "$ROOT/scripts/build-android" 2>"$TMP_DIR/signed.err"; then
  printf 'expected already-signed compile output to fail\n' >&2
  exit 1
fi
assert_file_contains "$TMP_DIR/signed.err" "refusing already-signed compile output"
unset FLUTTER_OUTPUT_KIND
: >"$FLUTTER_LOG"
"$ROOT/scripts/build-android"

STATE_DIR=$BUILDBOX_STATE_DIR
export STATE_DIR
# shellcheck disable=SC1090
source "$BUILDBOX_STATE_DIR/spec.env"

[[ "$BUILDBOX_TARGETS" == "apk,aab" ]]
[[ "$BUILDBOX_CHECKOUT_REPOSITORY" == "boxliy/aviary" ]]
[[ "$(jq 'length' "$BUILDBOX_STATE_DIR/unsigned-manifest.json")" == "2" ]]
[[ ! -e "$BUILDBOX_STATE_DIR/artifacts.json" ]]
assert_file_contains "$GITHUB_OUTPUT" "checkout_repository=boxliy/aviary"
assert_file_contains "$GITHUB_OUTPUT" "commit_sha=1111111111111111111111111111111111111111"
assert_file_contains "$GITHUB_OUTPUT" "targets=apk,aab"
[[ "$(cat "$GITHUB_ENV")" == "UNCHANGED=1" ]]
assert_file_contains "$FLUTTER_LOG" "build apk --release"
assert_file_contains "$FLUTTER_LOG" "build appbundle --release"
assert_file_contains "$FLUTTER_LOG" "SWAN_ANDROID_APPLICATION_ID=com.example_alpha"
assert_file_contains "$FLUTTER_LOG" "SWAN_APP_DISPLAY_NAME=Alpha\\ App"
assert_file_contains "$FLUTTER_LOG" "--dart-define=SWAN_EXPECTED_APP_ID=app-alpha"
assert_file_not_contains "$CURL_LOG" "https://oss.example/upload.apk"
assert_file_not_contains "$CURL_LOG" "https://oss.example/upload.aab"
assert_file_contains "$CURL_LOG" "/api/v1/buildbox/runs/401/callback"
assert_file_contains "$FLUTTER_LOG" "android.permission.CAMERA"
assert_file_contains "$FLUTTER_LOG" "android.permission.ACCESS_FINE_LOCATION"
assert_file_contains "$FLUTTER_LOG" "android.permission.USE_BIOMETRIC"
assert_file_contains "$FLUTTER_LOG" 'android:scheme="com.example-alpha"'
assert_file_not_contains "$CURL_LOG" "contract-token"
jq -e '
  .status == "running" and
  .githubRunId == 987654321 and
  .artifacts == [] and
  ((keys | sort) == ["artifacts", "githubRunId", "status"])
' "$PREPARE_STATE/callback-running.json" >/dev/null
jq -e '
  .status == "failed" and
  .githubRunId == 987654321 and
  .artifacts == [] and
  .errorCode == "BUILD_FAILED"
' "$BUILDBOX_STATE_DIR/callback-failed.json" >/dev/null

CURL_LOG="$TMP_DIR/curl-aab.log"
FLUTTER_LOG="$TMP_DIR/flutter-aab.log"
BUILDBOX_STATE_DIR="$TMP_DIR/state-aab"
GITHUB_OUTPUT="$TMP_DIR/github-output-aab.log"
export CURL_LOG FLUTTER_LOG BUILDBOX_STATE_DIR GITHUB_OUTPUT
mkdir -p "$BUILDBOX_STATE_DIR"

export MOCK_GIT_HEAD='2222222222222222222222222222222222222222'
"$ROOT/scripts/load-build-spec" 102:402
"$ROOT/scripts/export-job-inputs" compile "$TMP_DIR/compile-input-aab"
rm -rf "$BUILDBOX_STATE_DIR"
mkdir -p "$BUILDBOX_STATE_DIR"
cp -a "$TMP_DIR/compile-input-aab/." "$BUILDBOX_STATE_DIR/"
"$ROOT/scripts/build-android"
if "$ROOT/scripts/sign-android" 2>"$TMP_DIR/aab-sign.err"; then
  printf 'expected aab unsigned signing to fail\n' >&2
  exit 1
fi
assert_file_contains "$TMP_DIR/aab-sign.err" "signing material is not configured"
"$ROOT/scripts/report-result" failed "signing material is not configured"
assert_file_contains "$FLUTTER_LOG" "build appbundle --release"
assert_file_contains "$FLUTTER_LOG" "SWAN_ANDROID_APPLICATION_ID=com.example.beta"
assert_file_contains "$FLUTTER_LOG" "SWAN_APP_DISPLAY_NAME=Beta\\ App"
assert_file_contains "$FLUTTER_LOG" "--dart-define=SWAN_EXPECTED_APP_ID=app-beta"
assert_file_contains "$FLUTTER_LOG" "android.permission.POST_NOTIFICATIONS"
assert_file_not_contains "$CURL_LOG" "https://oss.example/upload.aab"
assert_file_contains "$GITHUB_OUTPUT" "checkout_repository=boxliy/aviary"
jq -e '.status == "failed" and .artifacts == []' \
  "$BUILDBOX_STATE_DIR/callback-failed.json" >/dev/null

CURL_LOG="$TMP_DIR/curl-mismatch.log"
BUILDBOX_STATE_DIR="$TMP_DIR/state-mismatch"
GITHUB_OUTPUT="$TMP_DIR/github-output-mismatch.log"
export CURL_LOG BUILDBOX_STATE_DIR GITHUB_OUTPUT
mkdir -p "$BUILDBOX_STATE_DIR"

export MOCK_GIT_HEAD='3333333333333333333333333333333333333333'
"$ROOT/scripts/load-build-spec" 101:401
"$ROOT/scripts/export-job-inputs" compile "$TMP_DIR/compile-input-mismatch"
rm -rf "$BUILDBOX_STATE_DIR"
mkdir -p "$BUILDBOX_STATE_DIR"
cp -a "$TMP_DIR/compile-input-mismatch/." "$BUILDBOX_STATE_DIR/"
if "$ROOT/scripts/build-android" 2>"$TMP_DIR/mismatch.err"; then
  printf 'expected commit mismatch to fail\n' >&2
  exit 1
fi
assert_file_contains "$TMP_DIR/mismatch.err" "does not match spec commit"
"$ROOT/scripts/report-result" failed "commit mismatch"
jq -e '
  .status == "failed" and
  .githubRunId == 987654321 and
  .artifacts == [] and
  .errorCode == "BUILD_FAILED" and
  .errorMessage == "commit mismatch" and
  ((keys | sort) == ["artifacts", "errorCode", "errorMessage", "githubRunId", "status"])
' "$BUILDBOX_STATE_DIR/callback-failed.json" >/dev/null

BUILDBOX_STATE_DIR="$TMP_DIR/state-tampered"
GITHUB_OUTPUT="$TMP_DIR/github-output-tampered.log"
export BUILDBOX_STATE_DIR GITHUB_OUTPUT
mkdir -p "$BUILDBOX_STATE_DIR"
if "$ROOT/scripts/load-build-spec" 103:403 2>"$TMP_DIR/tampered.err"; then
  printf 'expected a mismatched spec hash to fail\n' >&2
  exit 1
fi
assert_file_contains "$TMP_DIR/tampered.err" "specHash does not match config"

# Public rejection reports failed and never writes a running callback.
CURL_LOG="$TMP_DIR/curl-public.log"
BUILDBOX_STATE_DIR="$TMP_DIR/state-public"
GITHUB_OUTPUT="$TMP_DIR/github-output-public.log"
export CURL_LOG BUILDBOX_STATE_DIR GITHUB_OUTPUT
mkdir -p "$BUILDBOX_STATE_DIR"
export MOCK_GIT_HEAD='1111111111111111111111111111111111111111'
"$ROOT/scripts/load-build-spec" 101:401
printf '%s\n' 'public repository cannot carry unsigned build artifacts' >"$BUILDBOX_STATE_DIR/prepare-failure.txt"
"$ROOT/scripts/report-result" failed "$(head -n 1 "$BUILDBOX_STATE_DIR/prepare-failure.txt")"
if [[ -e "$BUILDBOX_STATE_DIR/callback-running.json" ]]; then
  printf 'public rejection must not report running\n' >&2
  exit 1
fi
jq -e '
  .status == "failed" and
  .githubRunId == 987654321 and
  .artifacts == [] and
  .errorCode == "BUILD_FAILED" and
  .errorMessage == "public repository cannot carry unsigned build artifacts"
' "$BUILDBOX_STATE_DIR/callback-failed.json" >/dev/null

printf 'contract tests passed\n'
