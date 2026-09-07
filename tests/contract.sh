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

BUILD_JOB=$(sed -n '/^  build:/,/^  finalize:/p' "$ROOT/.github/workflows/build.yml")
if grep -F 'HAWK_BUILDBOX_TOKEN' <<<"$BUILD_JOB" >/dev/null; then
  printf 'build job must not receive the Hawk service token\n' >&2
  exit 1
fi

export MOCK_GIT_HEAD='1111111111111111111111111111111111111111'
"$ROOT/scripts/load-build-spec" 101:401
"$ROOT/scripts/report-result" running
"$ROOT/scripts/build-android"
"$ROOT/scripts/upload-oss"
"$ROOT/scripts/report-result" succeeded

source "$BUILDBOX_STATE_DIR/spec.env"

[[ "$BUILDBOX_TARGETS" == "android_apk,android_aab" ]]
[[ "$BUILDBOX_CHECKOUT_REPOSITORY" == "boxliy/aviary" ]]
[[ "$(jq 'length' "$BUILDBOX_STATE_DIR/artifacts.json")" == "2" ]]
assert_file_contains "$GITHUB_OUTPUT" "checkout_repository=boxliy/aviary"
assert_file_contains "$GITHUB_OUTPUT" "commit_sha=1111111111111111111111111111111111111111"
assert_file_contains "$GITHUB_OUTPUT" "targets=android_apk,android_aab"
[[ "$(cat "$GITHUB_ENV")" == "UNCHANGED=1" ]]
assert_file_contains "$FLUTTER_LOG" "build apk --release"
assert_file_contains "$FLUTTER_LOG" "build appbundle --release"
assert_file_contains "$FLUTTER_LOG" "SWAN_ANDROID_APPLICATION_ID=com.example_alpha"
assert_file_contains "$FLUTTER_LOG" "SWAN_APP_DISPLAY_NAME=Alpha\\ App"
assert_file_contains "$FLUTTER_LOG" "--dart-define=SWAN_EXPECTED_APP_ID=app-alpha"
assert_file_contains "$CURL_LOG" "https://oss.example/upload.apk"
assert_file_contains "$CURL_LOG" "https://oss.example/upload.aab"
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
' "$BUILDBOX_STATE_DIR/callback-running.json" >/dev/null
jq -e '
  .status == "succeeded" and
  .githubRunId == 987654321 and
  (.artifacts | length) == 2 and
  ((keys | sort) == ["artifacts", "githubRunId", "status"]) and
  (any(.artifacts[]; .target == "android_apk" and .fileName == "swan-release.apk" and .contentType == "application/vnd.android.package-archive" and .objectKey == "builds/spec-apk-1/build-apk-1/android_apk.apk" and .byteSize == 13 and (.sha256 | test("^sha256:[0-9a-f]{64}$")))) and
  (any(.artifacts[]; .target == "android_aab" and .fileName == "swan-release.aab" and .contentType == "application/octet-stream" and .objectKey == "builds/spec-apk-1/build-apk-1/android_aab.aab" and .byteSize == 13 and (.sha256 | test("^sha256:[0-9a-f]{64}$"))))
' "$BUILDBOX_STATE_DIR/callback-succeeded.json" >/dev/null

CURL_LOG="$TMP_DIR/curl-aab.log"
FLUTTER_LOG="$TMP_DIR/flutter-aab.log"
BUILDBOX_STATE_DIR="$TMP_DIR/state-aab"
GITHUB_OUTPUT="$TMP_DIR/github-output-aab.log"
export CURL_LOG FLUTTER_LOG BUILDBOX_STATE_DIR GITHUB_OUTPUT
mkdir -p "$BUILDBOX_STATE_DIR"

export MOCK_GIT_HEAD='2222222222222222222222222222222222222222'
"$ROOT/scripts/load-build-spec" 102:402
"$ROOT/scripts/build-android"
printf '%s' 'after-build-change' >>"$BUILDBOX_STATE_DIR/artifacts/swan-release.aab"
"$ROOT/scripts/upload-oss"
"$ROOT/scripts/report-result" succeeded
assert_file_contains "$FLUTTER_LOG" "build appbundle --release"
assert_file_contains "$FLUTTER_LOG" "SWAN_ANDROID_APPLICATION_ID=com.example.beta"
assert_file_contains "$FLUTTER_LOG" "SWAN_APP_DISPLAY_NAME=Beta\\ App"
assert_file_contains "$FLUTTER_LOG" "--dart-define=SWAN_EXPECTED_APP_ID=app-beta"
assert_file_contains "$FLUTTER_LOG" "android.permission.POST_NOTIFICATIONS"
assert_file_contains "$CURL_LOG" "https://oss.example/upload.aab"
assert_file_contains "$GITHUB_OUTPUT" "checkout_repository=boxliy/aviary"
ACTUAL_AAB_HASH="sha256:$(sha256sum "$BUILDBOX_STATE_DIR/artifacts/swan-release.aab" | awk '{print $1}')"
jq -e --arg hash "$ACTUAL_AAB_HASH" '.artifacts[0].sha256 == $hash' \
  "$BUILDBOX_STATE_DIR/callback-succeeded.json" >/dev/null

CURL_LOG="$TMP_DIR/curl-mismatch.log"
BUILDBOX_STATE_DIR="$TMP_DIR/state-mismatch"
GITHUB_OUTPUT="$TMP_DIR/github-output-mismatch.log"
export CURL_LOG BUILDBOX_STATE_DIR GITHUB_OUTPUT
mkdir -p "$BUILDBOX_STATE_DIR"

export MOCK_GIT_HEAD='3333333333333333333333333333333333333333'
"$ROOT/scripts/load-build-spec" 101:401
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

printf 'contract tests passed\n'
