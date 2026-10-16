#!/usr/bin/env bash
# Shared Spec v1 target naming for buildbox scripts.
# Canonical Hawk targets: apk, aab, ipa. No legacy aliases are accepted.

targets_canonicalize_json() {
  jq -cer '
    . as $targets |
    select(type == "array" and length >= 1 and length <= 2) |
    select(all(.[]; . == "apk" or . == "aab" or . == "ipa")) |
    select(. == (sort | unique)) | select((index("ipa") == null) or length == 1)
  '
}

target_extension() {
  local target=$1
  case "$target" in
    apk) printf '%s' 'apk' ;;
    aab) printf '%s' 'aab' ;;
    ipa) printf '%s' 'ipa' ;;
    *) return 1 ;;
  esac
}

target_content_type() {
  local target=$1
  case "$target" in
    apk) printf '%s' 'application/vnd.android.package-archive' ;;
    aab | ipa) printf '%s' 'application/octet-stream' ;;
    *) return 1 ;;
  esac
}

target_artifact_basename() {
  local target=$1
  case "$target" in
    apk) printf '%s' 'swan-release.apk' ;;
    aab) printf '%s' 'swan-release.aab' ;;
    ipa) printf '%s' 'swan-release.ipa' ;;
    *) return 1 ;;
  esac
}

target_unsigned_glob() {
  local target=$1
  case "$target" in
    apk) printf '%s' 'build/app/outputs/flutter-apk/app-release.apk' ;;
    aab) printf '%s' 'build/app/outputs/bundle/release/app-release.aab' ;;
    *) return 1 ;;
  esac
}

target_object_key_suffix() {
  local target=$1
  local ext
  ext=$(target_extension "$target") || return 1
  printf '%s.%s' "$target" "$ext"
}
