#!/usr/bin/env bash
set -Eeuo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
TMP_DIR=$(mktemp -d)

export PATH="$ROOT/tests/bin:$PATH"
export FIXTURE_DIR="$ROOT/tests/fixtures"
export HAWK_BASE_URL='https://hawk.example'
export BUILDBOX_STATE_DIR="$TMP_DIR/state"
export ACTIONS_ID_TOKEN_REQUEST_TOKEN='oidc-request-token'
export ACTIONS_ID_TOKEN_REQUEST_URL='https://oidc.example/token?request=1'
export BUILDBOX_RUN_ID=401
export CURL_LOG="$TMP_DIR/curl.log"
export FLUTTER_LOG="$TMP_DIR/flutter.log"
export GITHUB_WORKSPACE="$TMP_DIR/workspace"
export GITHUB_OUTPUT="$TMP_DIR/github-output.log"
export GITHUB_ENV="$TMP_DIR/github-env.log"
export BUILDBOX_GITHUB_RUN_ID=987654321
printf '%s\n' 'UNCHANGED=1' >"$GITHUB_ENV"

mkdir -p "$GITHUB_WORKSPACE/aviary-source/.git"
mkdir -p "$GITHUB_WORKSPACE/aviary-source/waterfowl/apps/swan"
# The adapter has its own real digest/signature tests in Aviary. This suite
# substitutes its source executable to exercise buildbox's invocation boundary.
mkdir -p "$GITHUB_WORKSPACE/aviary-source/waterfowl/tools"
printf '%s\n' 'import sys; assert sys.argv[1] == "--spec" and sys.argv[3] == "--source"' >"$GITHUB_WORKSPACE/aviary-source/waterfowl/tools/build_spec_adapter.py"
printf '%s\n' 'fixture' >"$GITHUB_WORKSPACE/aviary-source/waterfowl/pubspec.lock"
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

use_finalize_credential() {
  "$ROOT/scripts/exchange-stage" finalize >/dev/null
  set -a
  # shellcheck disable=SC1090
  source "$GITHUB_ENV"
  set +a
  export HAWK_CALLBACK_STAGE=finalize
  [[ "${HAWK_STAGE_TOKEN:-}" == stage-finalize-* ]] || {
    printf 'finalize exchange did not replace the stage token\n' >&2
    exit 1
  }
}

COMPILE_JOB=$(sed -n '/^  compile:/,/^  sign:/p' "$ROOT/.github/workflows/build.yml")
if [[ -z "$COMPILE_JOB" ]]; then
  COMPILE_JOB=$(sed -n '/^  build:/,/^  finalize:/p' "$ROOT/.github/workflows/build.yml")
fi
if grep -F 'HAWK_BUILDBOX_TOKEN' <<<"$COMPILE_JOB" >/dev/null; then
  printf 'compile job must not receive the Hawk service token\n' >&2
  exit 1
fi
if grep -F 'id-token: write' <<<"$COMPILE_JOB" >/dev/null; then
  printf 'compile job must not request an Actions OIDC token\n' >&2
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
if ! grep -F 'scripts/exchange-stage prepare' <<<"$PREPARE_JOB" >/dev/null; then
  printf 'prepare must exchange a stage credential before reading the spec\n' >&2
  exit 1
fi
if grep -F 'HAWK_BUILDBOX_TOKEN' "$ROOT/.github/workflows/build.yml" >/dev/null; then
  printf 'workflow must not send the shared buildbox bearer\n' >&2
  exit 1
fi
if ! grep -F "github.event_name == 'workflow_dispatch'" <<<"$PREPARE_JOB" >/dev/null; then
  printf 'prepare must skip the push event GitHub sends when the workflow file changes\n' >&2
  exit 1
fi
TRIGGER=$(awk '/^on:/{flag=1;next}/^permissions:/{flag=0}flag' "$ROOT/.github/workflows/build.yml")
PUSH_TRIGGER=$(awk '/^  push:/{flag=1;next}/^[^ ]/{flag=0}flag' <<<"$TRIGGER")
if ! grep -E -q '^[[:space:]]*-[[:space:]]+main$' <<<"$PUSH_TRIGGER"; then
  printf 'push trigger must be limited to the main branch\n' >&2
  exit 1
fi
if ! grep -F '.github/workflows/build.yml' <<<"$PUSH_TRIGGER" >/dev/null; then
  printf 'push trigger must keep the workflow path filter\n' >&2
  exit 1
fi
SIGN_JOB=$(sed -n '/^  sign:/,/^  finalize:/p' "$ROOT/.github/workflows/build.yml")
FINALIZE_JOB=$(sed -n '/^  finalize:/,$p' "$ROOT/.github/workflows/build.yml")
if ! grep -F 'scripts/exchange-stage finalize' <<<"$FINALIZE_JOB" >/dev/null; then
  printf 'finalize must exchange its own stage credential\n' >&2
  exit 1
fi
if ! grep -F 'scripts/request-upload' <<<"$FINALIZE_JOB" >/dev/null; then
  printf 'finalize must request upload grants separately from the spec read\n' >&2
  exit 1
fi
if ! grep -F 'public repository cannot carry unsigned build artifacts' <<<"$PREPARE_JOB" >/dev/null; then
  printf 'prepare must fail closed on a public repository\n' >&2
  exit 1
fi
prepare_public=$(grep -n -F 'public repository cannot carry unsigned build artifacts' <<<"$PREPARE_JOB" | head -n 1 | cut -d: -f1)
if [[ -z "$prepare_public" ]]; then
  printf 'prepare must reject a public repository before later jobs\n' >&2
  exit 1
fi
if grep -F "needs.prepare.result == 'success'" <<<"$FINALIZE_JOB" >/dev/null \
  && grep -F 'if:' <<<"$FINALIZE_JOB" | head -n 1 | grep -F "needs.prepare.result == 'success'" >/dev/null; then
  printf 'finalize job must run after prepare failure so Hawk receives one terminal callback\n' >&2
  exit 1
fi
if ! grep -F "github.event_name == 'workflow_dispatch'" <<<"$FINALIZE_JOB" >/dev/null; then
  printf 'finalize must run for workflow_dispatch even when prepare fails\n' >&2
  exit 1
fi
if ! grep -F "needs.prepare.result != 'skipped'" <<<"$FINALIZE_JOB" >/dev/null; then
  printf 'finalize must skip the push event that never starts prepare\n' >&2
  exit 1
fi
if ! grep -F 'failure_reason:' <<<"$PREPARE_JOB" >/dev/null; then
  printf 'prepare must publish a failure reason as a job output\n' >&2
  exit 1
fi
if grep -F 'prepare-failure.txt' <<<"$PREPARE_JOB$FINALIZE_JOB" >/dev/null; then
  printf 'prepare failure must not depend on a runner-local file\n' >&2
  exit 1
fi
if grep -F 'scripts/report-result' <<<"$PREPARE_JOB" >/dev/null; then
  printf 'prepare must not callback with the prepare credential\n' >&2
  exit 1
fi
finalize_exchange=$(grep -n -F 'scripts/exchange-stage finalize' <<<"$FINALIZE_JOB" | head -n 1 | cut -d: -f1)
finalize_restore=$(grep -n -F 'actions/download-artifact' <<<"$FINALIZE_JOB" | head -n 1 | cut -d: -f1)
if [[ -z "$finalize_exchange" || -z "$finalize_restore" || "$finalize_exchange" -ge "$finalize_restore" ]]; then
  printf 'finalize must exchange a credential before restoring any artifact\n' >&2
  exit 1
fi
if ! grep -F 'needs.prepare.outputs.failure_reason' <<<"$FINALIZE_JOB" >/dev/null; then
  printf 'prepare failure callback must use the prepare job output\n' >&2
  exit 1
fi
if ! grep -F "needs.prepare.result == 'failure'" <<<"$FINALIZE_JOB" >/dev/null; then
  printf 'finalize must report prepare failure with the finalize credential\n' >&2
  exit 1
fi
if ! grep -F "needs.compile.result == 'cancelled'" <<<"$FINALIZE_JOB" >/dev/null \
  || ! grep -F "needs.sign.result == 'cancelled'" <<<"$FINALIZE_JOB" >/dev/null; then
  printf 'finalize must report compile or sign cancellation\n' >&2
  exit 1
fi
if ! grep -F 'HAWK_CALLBACK_STAGE: finalize' <<<"$FINALIZE_JOB" >/dev/null; then
  printf 'finalize callbacks must name the finalize stage\n' >&2
  exit 1
fi
finalize_running=$(grep -n -F 'scripts/report-result running' <<<"$FINALIZE_JOB" | head -n 1 | cut -d: -f1)
finalize_success=$(grep -n -F 'scripts/report-result succeeded' <<<"$FINALIZE_JOB" | head -n 1 | cut -d: -f1)
mapfile -t finalize_failures < <(grep -n -F 'scripts/report-result failed' <<<"$FINALIZE_JOB" | cut -d: -f1)
if [[ -z "$finalize_exchange" || -z "$finalize_running" || -z "$finalize_success" || ${#finalize_failures[@]} -lt 3 ]]; then
  printf 'finalize must exchange a credential before running, success, and failure callbacks\n' >&2
  exit 1
fi
finalize_prepare_failed=${finalize_failures[0]}
finalize_cancel=${finalize_failures[1]}
finalize_failed=${finalize_failures[2]}
if [[ "$finalize_exchange" -ge "$finalize_prepare_failed" || "$finalize_prepare_failed" -ge "$finalize_cancel" || "$finalize_cancel" -ge "$finalize_restore" ]]; then
  printf 'prepare failure and cancellation callbacks must follow the finalize exchange and precede artifact restore\n' >&2
  exit 1
fi
if [[ "$finalize_restore" -ge "$finalize_running" || "$finalize_running" -ge "$finalize_success" || "$finalize_success" -ge "$finalize_failed" ]]; then
  printf 'success-path callbacks must follow artifact restore and the finalize exchange\n' >&2
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
export BUILDBOX_RUN_ID=401
"$ROOT/scripts/exchange-stage" prepare >/dev/null
set -a
# shellcheck disable=SC1090
source "$GITHUB_ENV"
set +a
[[ -n "${HAWK_STAGE_TOKEN:-}" ]] || { printf 'prepare exchange did not publish a stage token\n' >&2; exit 1; }
"$ROOT/scripts/load-build-spec" 101:401
if jq -e 'has("uploads") and (.uploads | type == "array" and length > 0)' "$BUILDBOX_STATE_DIR/spec-response.json" >/dev/null; then
  printf 'prepare spec response must not include uploads\n' >&2
  exit 1
fi
use_finalize_credential
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
assert_file_contains "$TMP_DIR/unsigned.err" "signing failed; no signed delivery was authorized"
if [[ -e "$BUILDBOX_STATE_DIR/artifacts.json" || -e "$BUILDBOX_STATE_DIR/sign-proof.json" ]]; then
  printf 'failed signing must not write a success proof\n' >&2
  exit 1
fi
use_finalize_credential
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
assert_file_contains "$TMP_DIR/material.err" "signing failed; no signed delivery was authorized"
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

[[ "$BUILDBOX_TARGETS" == "aab,apk" ]]
[[ "$BUILDBOX_CHECKOUT_REPOSITORY" == "boxliy/aviary" ]]
[[ "$(jq 'length' "$BUILDBOX_STATE_DIR/unsigned-manifest.json")" == "2" ]]
[[ ! -e "$BUILDBOX_STATE_DIR/artifacts.json" ]]
assert_file_contains "$GITHUB_OUTPUT" "checkout_repository=boxliy/aviary"
assert_file_contains "$GITHUB_OUTPUT" "commit_sha=1111111111111111111111111111111111111111"
assert_file_contains "$GITHUB_OUTPUT" "targets=aab,apk"
grep -q '^UNCHANGED=1$' "$GITHUB_ENV"
grep -q '^HAWK_STAGE_TOKEN=' "$GITHUB_ENV"
assert_file_contains "$FLUTTER_LOG" "build apk --release --no-pub --build-name=1.2.3 --build-number=7"
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
assert_file_contains "$CURL_LOG" "/api/v1/buildbox/auth/exchange"
if grep -F 'HAWK_BUILDBOX_TOKEN' "$CURL_LOG" >/dev/null; then
  printf 'prepare must not send the shared bearer\n' >&2
  exit 1
fi
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
export BUILDBOX_RUN_ID=402
"$ROOT/scripts/exchange-stage" prepare >/dev/null
set -a
# shellcheck disable=SC1090
source "$GITHUB_ENV"
set +a
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
assert_file_contains "$TMP_DIR/aab-sign.err" "signing failed; no signed delivery was authorized"
use_finalize_credential
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
export BUILDBOX_RUN_ID=401
"$ROOT/scripts/exchange-stage" prepare >/dev/null
set -a
# shellcheck disable=SC1090
source "$GITHUB_ENV"
set +a
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
use_finalize_credential
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
export BUILDBOX_RUN_ID=403
"$ROOT/scripts/exchange-stage" prepare >/dev/null
set -a
# shellcheck disable=SC1090
source "$GITHUB_ENV"
set +a
if "$ROOT/scripts/load-build-spec" 103:403 2>"$TMP_DIR/tampered.err"; then
  printf 'expected a mismatched spec hash to fail\n' >&2
  exit 1
fi
assert_file_contains "$TMP_DIR/tampered.err" "specHash does not match config"

# Public rejection reports failed without a spec env or a running callback.
# Finalize writes only the platform run id before this callback.
CURL_LOG="$TMP_DIR/curl-public.log"
BUILDBOX_STATE_DIR="$TMP_DIR/state-public"
GITHUB_OUTPUT="$TMP_DIR/github-output-public.log"
export CURL_LOG BUILDBOX_STATE_DIR GITHUB_OUTPUT
mkdir -p "$BUILDBOX_STATE_DIR"
export BUILDBOX_RUN_ID=401
use_finalize_credential
"$ROOT/scripts/report-result" failed "public repository cannot carry unsigned build artifacts"
if [[ -e "$BUILDBOX_STATE_DIR/callback-running.json" || -e "$BUILDBOX_STATE_DIR/spec.env" ]]; then
  printf 'public rejection must not report running or require a spec env\n' >&2
  exit 1
fi
jq -e '
  .status == "failed" and
  .githubRunId == 987654321 and
  .artifacts == [] and
  .errorCode == "BUILD_FAILED" and
  .errorMessage == "public repository cannot carry unsigned build artifacts"
' "$BUILDBOX_STATE_DIR/callback-failed.json" >/dev/null

# Cancellation uses the same artifact-free failed callback. Hawk has no cancelled status.
CURL_LOG="$TMP_DIR/curl-cancel.log"
BUILDBOX_STATE_DIR="$TMP_DIR/state-cancel"
export CURL_LOG BUILDBOX_STATE_DIR
mkdir -p "$BUILDBOX_STATE_DIR"
export BUILDBOX_RUN_ID=401
use_finalize_credential
"$ROOT/scripts/report-result" failed "Buildbox workflow was cancelled in GitHub run $BUILDBOX_GITHUB_RUN_ID"
if [[ -e "$BUILDBOX_STATE_DIR/spec.env" ]]; then
  printf 'cancellation callback must not require a spec env\n' >&2
  exit 1
fi
jq -e '
  .status == "failed" and
  .artifacts == [] and
  .errorMessage == "Buildbox workflow was cancelled in GitHub run 987654321"
' "$BUILDBOX_STATE_DIR/callback-failed.json" >/dev/null

# A platform run id reaches the same frozen Spec without a caller-supplied spec id.
CURL_LOG="$TMP_DIR/curl-run.log"
BUILDBOX_STATE_DIR="$TMP_DIR/state-run"
GITHUB_OUTPUT="$TMP_DIR/github-output-run.log"
export CURL_LOG BUILDBOX_STATE_DIR GITHUB_OUTPUT
mkdir -p "$BUILDBOX_STATE_DIR"
export MOCK_GIT_HEAD='1111111111111111111111111111111111111111'
export BUILDBOX_RUN_ID=401
"$ROOT/scripts/exchange-stage" prepare >/dev/null
set -a
# shellcheck disable=SC1090
source "$GITHUB_ENV"
set +a
"$ROOT/scripts/load-build-spec" 401
assert_file_contains "$CURL_LOG" '/api/v1/buildbox/runs/401/spec'
if grep -F '/build-specs/' "$CURL_LOG" >/dev/null; then
  printf 'a platform run id must not call the spec-id endpoint\n' >&2
  exit 1
fi

# A numeric runId is rejected before Hawk issues a credential.
jq -nc --arg oidcToken mock-oidc-token --argjson runId 401 --arg stage prepare \
  '{oidcToken:$oidcToken,runId:$runId,stage:$stage}' >"$TMP_DIR/numeric-run.json"
if curl --fail --silent --show-error --request POST --data-binary "@$TMP_DIR/numeric-run.json" \
  "$HAWK_BASE_URL/api/v1/buildbox/auth/exchange" >/dev/null 2>"$TMP_DIR/numeric-run.err"; then
  printf 'expected a numeric runId to be rejected\n' >&2
  exit 1
fi

# A prepare credential cannot record a callback. Hawk checks the stage, not a token prefix.
export HAWK_STAGE_TOKEN=stage-prepare-token
export HAWK_CALLBACK_STAGE=prepare
if "$ROOT/scripts/report-result" failed "prepare credential" >/dev/null 2>"$TMP_DIR/prepare-callback.err"; then
  printf 'expected a prepare credential to be rejected for callback\n' >&2
  exit 1
fi
assert_file_contains "$TMP_DIR/prepare-callback.err" "callback requires a finalize stage credential"

printf 'contract tests passed\n'
