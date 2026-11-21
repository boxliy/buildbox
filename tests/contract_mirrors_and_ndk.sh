#!/usr/bin/env bash
# Contract tests for recursive private boxliy/* Git mirror discovery, offline
# URL rewriting across HTTPS/SSH/.git-less forms, fail-closed mirror errors, and
# Android NDK sdkmanager retry/cleanup resilience.

MIRROR_REPO=$(mktemp -d)
mkdir -p "$MIRROR_REPO/.git/refs" "$MIRROR_REPO/waterfowl"
printf 'https://github.com/boxliy/nib.git\n' >"$MIRROR_REPO/waterfowl/pubspec.lock"
: >"$MOCK_LOG"
TOKEN_BASIC=$(printf 'x-access-token:%s' "source-token" | base64 | tr -d '\n')
BUILDBOX_SOURCE_TOKEN=source-token MOCK_TAGS=v1.0.0 MOCK_GIT_LOG="$MOCK_LOG" PATH="$MOCK_BIN:/usr/bin:/bin" \
  "$ROOT/scripts/checkout-source" "$MIRROR_REPO" latest >/dev/null
assert_file_contains "$MOCK_LOG" "clone --bare --quiet https://github.com/boxliy/nib.git $MIRROR_REPO/.git/buildbox-mirrors/boxliy/nib.git"
assert_file_contains "$MOCK_LOG" "http.extraheader=AUTHORIZATION: basic ${TOKEN_BASIC} -C $MIRROR_REPO checkout --detach --quiet v1.0.0"
if grep -F 'source-token@' "$MOCK_LOG" >/dev/null || grep -F 'https://source-token' "$MOCK_LOG" >/dev/null; then
  printf 'source token was embedded in the nib mirror URL\n' >&2
  exit 1
fi
unset BUILDBOX_SOURCE_TOKEN

APP_REPO=$(mktemp -d)
mkdir -p "$APP_REPO/.git/refs" "$APP_REPO/waterfowl"
printf 'https://github.com/boxliy/nib.git\n' >"$APP_REPO/waterfowl/pubspec.lock"
: >"$MOCK_LOG"
APP_BASIC=$(printf 'x-access-token:%s' "aviary-app-token" | base64 | tr -d '\n')
PAT_BASIC=$(printf 'x-access-token:%s' "dependency-token" | base64 | tr -d '\n')
SOURCE_REPO_TOKEN=aviary-app-token BUILDBOX_SOURCE_TOKEN=dependency-token MOCK_FAIL_FIRST_CLONE=1 MOCK_TAGS=v1.0.0 MOCK_GIT_LOG="$MOCK_LOG" PATH="$MOCK_BIN:/usr/bin:/bin" \
  "$ROOT/scripts/checkout-source" "$APP_REPO" latest >/dev/null
assert_file_contains "$MOCK_LOG" "http.extraheader=AUTHORIZATION: basic ${APP_BASIC} -C $APP_REPO checkout --detach --quiet v1.0.0"
assert_file_contains "$MOCK_LOG" "http.extraheader=AUTHORIZATION: basic ${APP_BASIC} clone --bare --quiet https://github.com/boxliy/nib.git"
assert_file_contains "$MOCK_LOG" "http.extraheader=AUTHORIZATION: basic ${PAT_BASIC} clone --bare --quiet https://github.com/boxliy/nib.git $APP_REPO/.git/buildbox-mirrors/boxliy/nib.git"
if grep -F 'aviary-app-token@' "$MOCK_LOG" >/dev/null || grep -F 'dependency-token@' "$MOCK_LOG" >/dev/null || grep -F 'https://aviary-app-token' "$MOCK_LOG" >/dev/null || grep -F 'https://dependency-token' "$MOCK_LOG" >/dev/null; then
  printf 'a credential was embedded in a git URL\n' >&2
  exit 1
fi
unset SOURCE_REPO_TOKEN BUILDBOX_SOURCE_TOKEN MOCK_FAIL_FIRST_CLONE

# (a) & (b) Nested workspace pubspec.yaml + standalone tools/swan_build/pubspec.lock
# across HTTPS/SSH and .git/.git-less URLs, deduplicating repos and ignoring metadata/comments.
MULTI_REPO=$(mktemp -d)
mkdir -p \
  "$MULTI_REPO/.git/refs" \
  "$MULTI_REPO/waterfowl/packages/swan_platform" \
  "$MULTI_REPO/waterfowl/apps/swan" \
  "$MULTI_REPO/waterfowl/tools/swan_build"
cat >"$MULTI_REPO/waterfowl/pubspec.lock" <<'EOF'
packages:
  nib_core:
    description:
      url: "https://github.com/boxliy/nib.git"
EOF
cat >"$MULTI_REPO/waterfowl/packages/swan_platform/pubspec.yaml" <<'EOF'
name: swan_platform
repository: https://github.com/boxliy/aviary
homepage: https://github.com/boxliy/waterfowl
issue_tracker: https://github.com/boxliy/aviary/issues
# url: https://github.com/boxliy/commented_out.git
dependencies:
  nib_ble:
    git:
      url: https://github.com/boxliy/nib # inline comment https://github.com/boxliy/ignored_inline.git
EOF
cat >"$MULTI_REPO/waterfowl/apps/swan/pubspec.yaml" <<'EOF'
name: swan
dependencies:
  antscan_plugin:
    git:
      url: git@github.com:boxliy/antscan
  nib_esc:
    git:
      url: git@github.com:boxliy/nib.git
EOF
cat >"$MULTI_REPO/waterfowl/tools/swan_build/pubspec.yaml" <<'EOF'
name: swan_build
dependencies:
  pxlab_codec:
    git:
      url: ssh://git@github.com/boxliy/pxlab
EOF
cat >"$MULTI_REPO/waterfowl/tools/swan_build/pubspec.lock" <<'EOF'
packages:
  antscan_cli:
    description:
      url: "ssh://git@github.com/boxliy/antscan.git"
EOF
: >"$MOCK_LOG"
SOURCE_REPO_TOKEN=aviary-app-token BUILDBOX_SOURCE_TOKEN=dependency-token MOCK_TAGS=v1.0.0 MOCK_GIT_LOG="$MOCK_LOG" PATH="$MOCK_BIN:/usr/bin:/bin" \
  "$ROOT/scripts/checkout-source" "$MULTI_REPO" latest >/dev/null
assert_file_contains "$MOCK_LOG" "clone --bare --quiet https://github.com/boxliy/antscan.git $MULTI_REPO/.git/buildbox-mirrors/boxliy/antscan.git"
assert_file_contains "$MOCK_LOG" "clone --bare --quiet https://github.com/boxliy/nib.git $MULTI_REPO/.git/buildbox-mirrors/boxliy/nib.git"
assert_file_contains "$MOCK_LOG" "clone --bare --quiet https://github.com/boxliy/pxlab.git $MULTI_REPO/.git/buildbox-mirrors/boxliy/pxlab.git"
assert_file_not_contains "$MOCK_LOG" "boxliy/aviary.git"
assert_file_not_contains "$MOCK_LOG" "boxliy/waterfowl.git"
assert_file_not_contains "$MOCK_LOG" "boxliy/commented_out.git"
assert_file_not_contains "$MOCK_LOG" "boxliy/ignored_inline.git"
mirror_clone_count=$(grep -c 'clone --bare --quiet' "$MOCK_LOG")
[[ "$mirror_clone_count" -eq 3 ]] || {
  printf 'expected 3 unique bare mirror clones, got %s\n' "$mirror_clone_count" >&2
  exit 1
}

# (c) Fail closed when cloning a discovered private Git dependency fails on all tokens.
FAIL_MIRROR_REPO=$(mktemp -d)
mkdir -p "$FAIL_MIRROR_REPO/.git/refs" "$FAIL_MIRROR_REPO/waterfowl/tools/swan_build"
cat >"$FAIL_MIRROR_REPO/waterfowl/tools/swan_build/pubspec.lock" <<'EOF'
packages:
  antscan_cli:
    description:
      url: "https://github.com/boxliy/antscan"
EOF
: >"$MOCK_LOG"
if SOURCE_REPO_TOKEN=aviary-app-token BUILDBOX_SOURCE_TOKEN=dependency-token MOCK_FAIL_ALL_CLONES=1 MOCK_TAGS=v1.0.0 MOCK_GIT_LOG="$MOCK_LOG" PATH="$MOCK_BIN:/usr/bin:/bin" \
  "$ROOT/scripts/checkout-source" "$FAIL_MIRROR_REPO" latest >/dev/null 2>"$TMP_DIR/mirror-fail.err"; then
  printf 'expected checkout-source to fail closed when mirror clone fails\n' >&2
  exit 1
fi
assert_file_contains "$TMP_DIR/mirror-fail.err" "checkout-source: failed to mirror private Git dependency: boxliy/antscan"
assert_file_contains "$MOCK_LOG" "http.extraheader=AUTHORIZATION: basic ${APP_BASIC} clone --bare --quiet https://github.com/boxliy/antscan.git"
assert_file_contains "$MOCK_LOG" "http.extraheader=AUTHORIZATION: basic ${PAT_BASIC} clone --bare --quiet https://github.com/boxliy/antscan.git"
if [[ -e "$FAIL_MIRROR_REPO/.git/buildbox-mirrors/boxliy/antscan.git" ]]; then
  printf 'failed mirror clone left partial mirror directory behind\n' >&2
  exit 1
fi

# Verify compile-runner URL rewriting across all 6 URL variants BEFORE swan_build dart pub get
# and waterfowl flutter pub get, plus legacy .git/buildbox-mirrors/nib.git compatibility.
OFFLINE_TEST_DIR=$(mktemp -d)
OFFLINE_GITCFG="$OFFLINE_TEST_DIR/gitconfig"
OFFLINE_SOURCE="$OFFLINE_TEST_DIR/aviary-source"
cp -a "$GITHUB_WORKSPACE/aviary-source/." "$OFFLINE_SOURCE/"

create_bare_fixture_mirror() {
  local work_dir=$1
  local bare_dir=$2
  local marker=$3
  "${GIT[@]}" init -b main --quiet "$work_dir"
  "${GIT[@]}" -C "$work_dir" config user.email fixture@example.invalid
  "${GIT[@]}" -C "$work_dir" config user.name "Buildbox Fixture"
  "${GIT[@]}" -C "$work_dir" config commit.gpgsign false
  printf '%s\n' "$marker" >"$work_dir/README.md"
  "${GIT[@]}" -C "$work_dir" add README.md
  "${GIT[@]}" -C "$work_dir" commit --quiet -m "$marker"
  mkdir -p "$(dirname "$bare_dir")"
  "${GIT[@]}" clone --bare --quiet "$work_dir" "$bare_dir"
  "${GIT[@]}" -C "$work_dir" rev-parse HEAD
}

NIB_MIRROR_SHA=$(create_bare_fixture_mirror "$OFFLINE_TEST_DIR/nib-src" "$OFFLINE_SOURCE/.git/buildbox-mirrors/boxliy/nib.git" "nib-fixture")
ANTSCAN_MIRROR_SHA=$(create_bare_fixture_mirror "$OFFLINE_TEST_DIR/antscan-src" "$OFFLINE_SOURCE/.git/buildbox-mirrors/boxliy/antscan.git" "antscan-fixture")

ORDER_BIN="$OFFLINE_TEST_DIR/bin"
mkdir -p "$ORDER_BIN"
ORDER_LOG="$OFFLINE_TEST_DIR/pub-order.log"
: >"$ORDER_LOG"

cat >"$ORDER_BIN/check_mirrors" <<'CHECK_EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
label=$1
nib_expected=$2
antscan_expected=$3
for repo_pair in "nib:$nib_expected" "antscan:$antscan_expected"; do
  repo=${repo_pair%%:*}
  expected=${repo_pair#*:}
  for url in \
    "https://github.com/boxliy/${repo}.git" \
    "https://github.com/boxliy/${repo}" \
    "git@github.com:boxliy/${repo}.git" \
    "git@github.com:boxliy/${repo}" \
    "ssh://git@github.com/boxliy/${repo}.git" \
    "ssh://git@github.com/boxliy/${repo}"; do
    resolved=$(git ls-remote "$url" HEAD | awk '{print $1}')
    [[ "$resolved" == "$expected" ]] || {
      printf '%s: URL %s resolved to %s, expected %s\n' "$label" "$url" "$resolved" "$expected" >&2
      exit 1
    }
  done
done
printf 'verified:%s:%s\n' "$label" "$PWD" >>"${ORDER_LOG:?}"
CHECK_EOF
chmod +x "$ORDER_BIN/check_mirrors"

cat >"$ORDER_BIN/dart" <<EOF
#!/usr/bin/env bash
set -Eeuo pipefail
if [[ "\${1:-}" == pub && "\${2:-}" == get && "\${3:-}" == --enforce-lockfile ]]; then
  "$ORDER_BIN/check_mirrors" dart-pub-get "$NIB_MIRROR_SHA" "$ANTSCAN_MIRROR_SHA"
  exit 0
fi
exec "$ROOT/tests/bin/dart" "\$@"
EOF
chmod +x "$ORDER_BIN/dart"

cat >"$ORDER_BIN/flutter" <<EOF
#!/usr/bin/env bash
set -Eeuo pipefail
if [[ "\${1:-}" == pub && "\${2:-}" == get && "\${3:-}" == --enforce-lockfile ]]; then
  "$ORDER_BIN/check_mirrors" flutter-pub-get "$NIB_MIRROR_SHA" "$ANTSCAN_MIRROR_SHA"
  exit 0
fi
exec "$ROOT/tests/bin/flutter" "\$@"
EOF
chmod +x "$ORDER_BIN/flutter"

OFFLINE_STATE="$OFFLINE_TEST_DIR/state"
mkdir -p "$OFFLINE_STATE"
cp -a "$TMP_DIR/compile-input/." "$OFFLINE_STATE/"
env -u HAWK_STAGE_TOKEN -u ACTIONS_ID_TOKEN_REQUEST_TOKEN \
  GIT_CONFIG_GLOBAL="$OFFLINE_GITCFG" \
  BUILDBOX_STATE_DIR="$OFFLINE_STATE" \
  BUILDBOX_SOURCE_ROOT="$OFFLINE_SOURCE" \
  FLUTTER_LOG="$OFFLINE_TEST_DIR/flutter.log" \
  MOCK_GIT_HEAD='1111111111111111111111111111111111111111' \
  ORDER_LOG="$ORDER_LOG" \
  PATH="$ORDER_BIN:$PATH" \
  "$ROOT/scripts/verify-compile-inputs"
assert_file_contains "$ORDER_LOG" "verified:dart-pub-get:$OFFLINE_SOURCE/waterfowl/tools/swan_build"
assert_file_contains "$ORDER_LOG" "verified:flutter-pub-get:$OFFLINE_SOURCE/waterfowl"

# Legacy .git/buildbox-mirrors/nib.git layout remains supported across all 6 URL variants,
# and stale mirror paths from a prior checkout are replaced cleanly.
LEGACY_SOURCE="$OFFLINE_TEST_DIR/legacy-source"
mkdir -p "$LEGACY_SOURCE/.git"
LEGACY_NIB_SHA=$(create_bare_fixture_mirror "$OFFLINE_TEST_DIR/legacy-nib-src" "$LEGACY_SOURCE/.git/buildbox-mirrors/nib.git" "legacy-nib-fixture")
(
  export GIT_CONFIG_GLOBAL="$OFFLINE_GITCFG"
  # shellcheck source=../scripts/lib/mirrors.sh
  source "$ROOT/scripts/lib/mirrors.sh"
  configure_source_mirrors "$LEGACY_SOURCE"
  for url in \
    "https://github.com/boxliy/nib.git" \
    "https://github.com/boxliy/nib" \
    "git@github.com:boxliy/nib.git" \
    "git@github.com:boxliy/nib" \
    "ssh://git@github.com/boxliy/nib.git" \
    "ssh://git@github.com/boxliy/nib"; do
    resolved=$("${GIT[@]}" ls-remote "$url" HEAD | awk '{print $1}')
    [[ "$resolved" == "$LEGACY_NIB_SHA" ]] || {
      printf 'legacy mirror URL %s resolved to %s, expected %s\n' "$url" "$resolved" "$LEGACY_NIB_SHA" >&2
      exit 1
    }
  done
)

# (d) Android NDK pre-install resilience in scripts/build-android:
# 1. Retries transient sdkmanager failures up to 3 attempts, cleaning partial ndk/<ver> and .temp
#    between retries, then skips sdkmanager once source.properties is present.
NDK_TEST_DIR=$(mktemp -d)
NDK_SOURCE="$NDK_TEST_DIR/aviary-source"
cp -a "$GITHUB_WORKSPACE/aviary-source/." "$NDK_SOURCE/"
mkdir -p "$NDK_SOURCE/waterfowl/apps/swan/android/app"
cat >"$NDK_SOURCE/waterfowl/apps/swan/android/app/build.gradle.kts" <<'EOF'
android {
    // ndkVersion = "25.0.0000000"
    ndkVersion = "28.2.13676358"
}
EOF

NDK_SDK="$NDK_TEST_DIR/android-sdk"
mkdir -p "$NDK_SDK/cmdline-tools/latest/bin" "$NDK_SDK/ndk/28.2.13676358" "$NDK_SDK/.temp"
printf 'stale-partial\n' >"$NDK_SDK/ndk/28.2.13676358/stale.tmp"
printf 'stale-zip\n' >"$NDK_SDK/.temp/stale.zip"
SDKM_LOG="$NDK_TEST_DIR/sdkmanager.log"
SDKM_COUNT_FILE="$NDK_TEST_DIR/sdkmanager.count"
: >"$SDKM_LOG"

cat >"$NDK_SDK/cmdline-tools/latest/bin/sdkmanager" <<'SDKM_EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
count=0
if [[ -f "${SDKM_COUNT_FILE:?}" ]]; then
  count=$(cat "$SDKM_COUNT_FILE")
fi
count=$((count + 1))
printf '%s' "$count" >"$SDKM_COUNT_FILE"
printf 'attempt=%s args=%s\n' "$count" "$*" >>"${SDKM_LOG:?}"

sdk_arg=${1#--sdk_root=}
pkg=$2
ver=${pkg#ndk;}
if [[ -e "$sdk_arg/ndk/$ver" || -e "$sdk_arg/.temp" || -e "$sdk_arg/ndk/.temp" ]]; then
  printf 'partial NDK or .temp was not cleaned before attempt %s\n' "$count" >&2
  exit 99
fi

if [[ "${SDKM_ALWAYS_FAIL:-0}" == "1" || "$count" -lt 3 ]]; then
  mkdir -p "$sdk_arg/ndk/$ver" "$sdk_arg/.temp/PackageOperation01" "$sdk_arg/ndk/.temp"
  printf 'corrupt\n' >"$sdk_arg/ndk/$ver/partial.bin"
  printf 'truncated\n' >"$sdk_arg/.temp/PackageOperation01/ndk.zip"
  printf 'Error on ZipFile unknown archive\n' >&2
  exit 1
fi

mkdir -p "$sdk_arg/ndk/$ver"
printf 'Pkg.Desc = Android NDK\nPkg.Revision = %s\n' "$ver" >"$sdk_arg/ndk/$ver/source.properties"
SDKM_EOF
chmod +x "$NDK_SDK/cmdline-tools/latest/bin/sdkmanager"

NDK_STATE="$NDK_TEST_DIR/state"
mkdir -p "$NDK_STATE"
cp -a "$TMP_DIR/compile-input/." "$NDK_STATE/"
NDK_FLUTTER_LOG="$NDK_TEST_DIR/flutter.log"
: >"$NDK_FLUTTER_LOG"

env -u HAWK_STAGE_TOKEN -u ACTIONS_ID_TOKEN_REQUEST_TOKEN \
  ANDROID_HOME="$NDK_SDK" \
  BUILDBOX_NDK_RETRY_DELAY=0 \
  BUILDBOX_STATE_DIR="$NDK_STATE" \
  BUILDBOX_SOURCE_ROOT="$NDK_SOURCE" \
  FLUTTER_LOG="$NDK_FLUTTER_LOG" \
  MOCK_GIT_HEAD='1111111111111111111111111111111111111111' \
  SDKM_COUNT_FILE="$SDKM_COUNT_FILE" \
  SDKM_LOG="$SDKM_LOG" \
  "$ROOT/scripts/build-android" >/dev/null 2>"$NDK_TEST_DIR/ndk-retry.err"

[[ "$(cat "$SDKM_COUNT_FILE")" == "3" ]] || {
  printf 'expected 3 sdkmanager attempts, got %s\n' "$(cat "$SDKM_COUNT_FILE")" >&2
  exit 1
}
[[ -f "$NDK_SDK/ndk/28.2.13676358/source.properties" ]] || {
  printf 'expected NDK source.properties after retry recovery\n' >&2
  exit 1
}
[[ ! -e "$NDK_SDK/.temp" && ! -e "$NDK_SDK/ndk/.temp" ]] || {
  printf 'expected .temp directories to be absent after install\n' >&2
  exit 1
}
assert_file_contains "$SDKM_LOG" "attempt=1 args=--sdk_root=$NDK_SDK ndk;28.2.13676358"
assert_file_contains "$SDKM_LOG" "attempt=3 args=--sdk_root=$NDK_SDK ndk;28.2.13676358"
assert_file_contains "$NDK_FLUTTER_LOG" "build apk --release"

# Re-running with source.properties already present must skip sdkmanager entirely.
env -u HAWK_STAGE_TOKEN -u ACTIONS_ID_TOKEN_REQUEST_TOKEN \
  ANDROID_HOME="$NDK_SDK" \
  BUILDBOX_NDK_RETRY_DELAY=0 \
  BUILDBOX_STATE_DIR="$NDK_STATE" \
  BUILDBOX_SOURCE_ROOT="$NDK_SOURCE" \
  FLUTTER_LOG="$NDK_FLUTTER_LOG" \
  MOCK_GIT_HEAD='1111111111111111111111111111111111111111' \
  SDKM_COUNT_FILE="$SDKM_COUNT_FILE" \
  SDKM_LOG="$SDKM_LOG" \
  "$ROOT/scripts/build-android" >/dev/null
[[ "$(cat "$SDKM_COUNT_FILE")" == "3" ]] || {
  printf 'sdkmanager ran again even though source.properties existed\n' >&2
  exit 1
}

# 2. Groovy build.gradle ndkVersion + flutter.ndkVersion resolution + ANDROID_SDK_ROOT fallback.
rm -f "$NDK_SOURCE/waterfowl/apps/swan/android/app/build.gradle.kts"
cat >"$NDK_SOURCE/waterfowl/apps/swan/android/build.gradle" <<'EOF'
android {
    ndkVersion '27.3.13750724'
}
EOF
rm -f "$SDKM_COUNT_FILE"
: >"$SDKM_LOG"
printf '2\n' >"$SDKM_COUNT_FILE"
env -u HAWK_STAGE_TOKEN -u ACTIONS_ID_TOKEN_REQUEST_TOKEN -u ANDROID_HOME \
  ANDROID_SDK_ROOT="$NDK_SDK" \
  BUILDBOX_NDK_RETRY_DELAY=0 \
  BUILDBOX_STATE_DIR="$NDK_STATE" \
  BUILDBOX_SOURCE_ROOT="$NDK_SOURCE" \
  FLUTTER_LOG="$NDK_FLUTTER_LOG" \
  MOCK_GIT_HEAD='1111111111111111111111111111111111111111' \
  SDKM_COUNT_FILE="$SDKM_COUNT_FILE" \
  SDKM_LOG="$SDKM_LOG" \
  "$ROOT/scripts/build-android" >/dev/null
[[ -f "$NDK_SDK/ndk/27.3.13750724/source.properties" ]] || {
  printf 'expected Groovy ndkVersion 27.3.13750724 to be installed via ANDROID_SDK_ROOT\n' >&2
  exit 1
}

rm -f "$NDK_SOURCE/waterfowl/apps/swan/android/build.gradle"
cat >"$NDK_SOURCE/waterfowl/apps/swan/android/app/build.gradle.kts" <<'EOF'
android {
    ndkVersion = flutter.ndkVersion
}
EOF
FAKE_FLUTTER_ROOT="$NDK_TEST_DIR/fake-flutter"
mkdir -p "$FAKE_FLUTTER_ROOT/packages/flutter_tools/gradle/src/main/kotlin"
cat >"$FAKE_FLUTTER_ROOT/packages/flutter_tools/gradle/src/main/kotlin/FlutterExtension.kt" <<'EOF'
class FlutterExtension {
    val ndkVersion: String = "29.0.13846066"
}
EOF
printf '2\n' >"$SDKM_COUNT_FILE"
env -u HAWK_STAGE_TOKEN -u ACTIONS_ID_TOKEN_REQUEST_TOKEN \
  ANDROID_HOME="$NDK_SDK" \
  FLUTTER_ROOT="$FAKE_FLUTTER_ROOT" \
  BUILDBOX_NDK_RETRY_DELAY=0 \
  BUILDBOX_STATE_DIR="$NDK_STATE" \
  BUILDBOX_SOURCE_ROOT="$NDK_SOURCE" \
  FLUTTER_LOG="$NDK_FLUTTER_LOG" \
  MOCK_GIT_HEAD='1111111111111111111111111111111111111111' \
  SDKM_COUNT_FILE="$SDKM_COUNT_FILE" \
  SDKM_LOG="$SDKM_LOG" \
  "$ROOT/scripts/build-android" >/dev/null
[[ -f "$NDK_SDK/ndk/29.0.13846066/source.properties" ]] || {
  printf 'expected flutter.ndkVersion 29.0.13846066 to be resolved and installed\n' >&2
  exit 1
}

# 3. Exhausting all 3 sdkmanager attempts fails closed, cleans partial dirs, and skips flutter build.
rm -rf "$NDK_SDK/ndk/29.0.13846066" "$SDKM_COUNT_FILE"
: >"$SDKM_LOG"
: >"$NDK_FLUTTER_LOG"
if env -u HAWK_STAGE_TOKEN -u ACTIONS_ID_TOKEN_REQUEST_TOKEN \
  ANDROID_HOME="$NDK_SDK" \
  FLUTTER_ROOT="$FAKE_FLUTTER_ROOT" \
  BUILDBOX_NDK_RETRY_DELAY=0 \
  BUILDBOX_STATE_DIR="$NDK_STATE" \
  BUILDBOX_SOURCE_ROOT="$NDK_SOURCE" \
  FLUTTER_LOG="$NDK_FLUTTER_LOG" \
  MOCK_GIT_HEAD='1111111111111111111111111111111111111111' \
  SDKM_ALWAYS_FAIL=1 \
  SDKM_COUNT_FILE="$SDKM_COUNT_FILE" \
  SDKM_LOG="$SDKM_LOG" \
  "$ROOT/scripts/build-android" >/dev/null 2>"$NDK_TEST_DIR/ndk-exhausted.err"; then
  printf 'expected exhausted sdkmanager retries to fail build-android\n' >&2
  exit 1
fi
[[ "$(cat "$SDKM_COUNT_FILE")" == "3" ]] || {
  printf 'expected 3 failed sdkmanager attempts, got %s\n' "$(cat "$SDKM_COUNT_FILE")" >&2
  exit 1
}
assert_file_contains "$NDK_TEST_DIR/ndk-exhausted.err" "failed to pre-install Android NDK via sdkmanager"
if [[ -e "$NDK_SDK/ndk/29.0.13846066" || -e "$NDK_SDK/.temp" || -e "$NDK_SDK/ndk/.temp" ]]; then
  printf 'exhausted sdkmanager retries left partial NDK or .temp behind\n' >&2
  exit 1
fi
assert_file_not_contains "$NDK_FLUTTER_LOG" "build apk"
