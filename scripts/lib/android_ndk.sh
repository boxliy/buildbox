#!/usr/bin/env bash
# Resolve declared Android ndkVersion and pre-install it via sdkmanager with
# bounded retries and partial-download cleanup before Gradle runs.

resolve_flutter_sdk_ndk_version() {
  local swan_dir=$1
  local flutter_root=''
  local candidate flutter_bin resolved_bin

  for candidate in \
    "$swan_dir/.fvm/flutter_sdk" \
    "${SOURCE_ROOT:-}/.fvm/flutter_sdk" \
    "${FLUTTER_ROOT:-}"; do
    if [[ -n "$candidate" && -d "$candidate/packages/flutter_tools" ]]; then
      flutter_root=$candidate
      break
    fi
  done

  if [[ -z "$flutter_root" ]] && flutter_bin=$(command -v flutter 2>/dev/null); then
    resolved_bin=$(readlink -f "$flutter_bin" 2>/dev/null || printf '%s\n' "$flutter_bin")
    candidate=$(cd "$(dirname "$resolved_bin")/.." 2>/dev/null && pwd || true)
    if [[ -n "$candidate" && -d "$candidate/packages/flutter_tools" ]]; then
      flutter_root=$candidate
    fi
  fi

  [[ -n "$flutter_root" ]] || return 0

  local ext_file
  for ext_file in \
    "$flutter_root/packages/flutter_tools/gradle/src/main/kotlin/FlutterExtension.kt" \
    "$flutter_root/packages/flutter_tools/lib/src/android/gradle_utils.dart"; do
    [[ -f "$ext_file" ]] || continue
    local found
    found=$(awk '
      {
        sub(/\/\/.*/, "")
        if (match($0, /ndkVersion[^"'\'']*["'\''][0-9]+(\.[0-9]+)+(-[A-Za-z0-9._-]+)?["'\'']/)) {
          s = substr($0, RSTART, RLENGTH)
          sub(/^[^"'\'']*["'\'']/, "", s)
          sub(/["'\'']$/, "", s)
          print s
          exit 0
        }
      }
    ' "$ext_file")
    if [[ -n "$found" ]]; then
      printf '%s\n' "$found"
      return 0
    fi
  done
}

extract_gradle_ndk_version() {
  local swan_dir=$1
  local gradle_files=()
  local candidate

  for candidate in \
    "$swan_dir"/android/app/build.gradle* \
    "$swan_dir"/android/build.gradle*; do
    [[ -f "$candidate" ]] || continue
    gradle_files+=("$candidate")
  done
  [[ ${#gradle_files[@]} -gt 0 ]] || return 0

  local file found
  for file in "${gradle_files[@]}"; do
    found=$(awk '
      {
        sub(/\/\/.*/, "")
        if (match($0, /(setNdkVersion|ndkVersion)[ \t]*(\(|=|[ \t])[ \t]*["'\''][0-9]+(\.[0-9]+)+(-[A-Za-z0-9._-]+)?["'\'']/)) {
          s = substr($0, RSTART, RLENGTH)
          sub(/^[^"'\'']*["'\'']/, "", s)
          sub(/["'\'']$/, "", s)
          print s
          exit 0
        }
      }
    ' "$file")
    if [[ -n "$found" && "$found" =~ ^[0-9]+(\.[0-9]+)+(-[A-Za-z0-9._-]+)?$ ]]; then
      printf '%s\n' "$found"
      return 0
    fi
  done

  for file in "${gradle_files[@]}"; do
    if awk '{ sub(/\/\/.*/, ""); if ($0 ~ /ndkVersion.*flutter\.ndkVersion/) { found = 1; exit 0 } } END { exit(found ? 0 : 1) }' "$file"; then
      found=$(resolve_flutter_sdk_ndk_version "$swan_dir")
      if [[ -n "$found" && "$found" =~ ^[0-9]+(\.[0-9]+)+(-[A-Za-z0-9._-]+)?$ ]]; then
        printf '%s\n' "$found"
        return 0
      fi
      break
    fi
  done
}

ensure_android_ndk() {
  local swan_dir=$1
  local ndk_version
  ndk_version=$(extract_gradle_ndk_version "$swan_dir")
  [[ -n "$ndk_version" ]] || return 0
  [[ "$ndk_version" =~ ^[0-9]+(\.[0-9]+)+(-[A-Za-z0-9._-]+)?$ ]] || return 1

  local sdk_root='' candidate
  for candidate in "${ANDROID_HOME:-}" "${ANDROID_SDK_ROOT:-}"; do
    if [[ -n "$candidate" && -x "$candidate/cmdline-tools/latest/bin/sdkmanager" ]]; then
      sdk_root=$candidate
      break
    fi
  done
  [[ -n "$sdk_root" ]] || return 0

  if [[ -f "$sdk_root/ndk/$ndk_version/source.properties" ]]; then
    return 0
  fi

  local sdkmanager="$sdk_root/cmdline-tools/latest/bin/sdkmanager"
  local max_attempts=3
  local delay=${BUILDBOX_NDK_RETRY_DELAY:-2}
  [[ "$delay" =~ ^[0-9]+([.][0-9]+)?$ ]] || delay=2

  local attempt
  for ((attempt = 1; attempt <= max_attempts; attempt++)); do
    rm -rf "$sdk_root/ndk/$ndk_version" "$sdk_root/.temp" "$sdk_root/ndk/.temp"
    if "$sdkmanager" --sdk_root="$sdk_root" "ndk;${ndk_version}" < <(printf 'y\ny\ny\ny\ny\n') \
      && [[ -f "$sdk_root/ndk/$ndk_version/source.properties" ]]; then
      return 0
    fi
    rm -rf "$sdk_root/ndk/$ndk_version" "$sdk_root/.temp" "$sdk_root/ndk/.temp"
    printf 'build-android: sdkmanager failed to install ndk;%s (attempt %s/%s)\n' \
      "$ndk_version" "$attempt" "$max_attempts" >&2
    if [[ "$attempt" -lt "$max_attempts" ]] && command -v sleep >/dev/null 2>&1 && [[ "$delay" != "0" ]]; then
      sleep "$delay"
    fi
  done

  return 1
}
