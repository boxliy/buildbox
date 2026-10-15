#!/usr/bin/env bash
# Shared Spec v1 target naming for buildbox scripts.
# Canonical Hawk targets: apk, aab, ipa. Legacy android_apk/android_aab are accepted at load time.

targets_canonicalize_json() {
  jq -cer '
    . as $targets |
    select(type == "array" and length >= 1 and length <= 2) |
    map(
      if . == "android_apk" then "apk"
      elif . == "android_aab" then "aab"
      else .
      end
    ) |
    select(all(.[]; . == "apk" or . == "aab" or . == "ipa")) |
    select((unique | length) == length)
  '
}

target_extension() {
  local target=$1
  case "$target" in
    apk | android_apk) printf '%s' 'apk' ;;
    aab | android_aab) printf '%s' 'aab' ;;
    ipa) printf '%s' 'ipa' ;;
    *) return 1 ;;
  esac
}

target_content_type() {
  local target=$1
  case "$target" in
    apk | android_apk) printf '%s' 'application/vnd.android.package-archive' ;;
    aab | android_aab | ipa) printf '%s' 'application/octet-stream' ;;
    *) return 1 ;;
  esac
}

target_artifact_basename() {
  local target=$1
  case "$target" in
    apk | android_apk) printf '%s' 'swan-release.apk' ;;
    aab | android_aab) printf '%s' 'swan-release.aab' ;;
    ipa) printf '%s' 'swan-release.ipa' ;;
    *) return 1 ;;
  esac
}

target_unsigned_glob() {
  local target=$1
  case "$target" in
    apk | android_apk) printf '%s' 'build/app/outputs/flutter-apk/app-release.apk' ;;
    aab | android_aab) printf '%s' 'build/app/outputs/bundle/release/app-release.aab' ;;
    *) return 1 ;;
  esac
}

target_object_key_suffix() {
  local target=$1
  local ext
  ext=$(target_extension "$target") || return 1
  printf '%s.%s' "$target" "$ext"
}
