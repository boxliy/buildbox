#!/usr/bin/env bash
# Retry one curl invocation when the failure is a transient transport or TLS
# error. Arguments are forwarded unchanged so callers keep their existing flags.
# Partial stdout from a failed attempt is discarded. Response bodies stay in a
# mode-0600 temporary file until the attempt finishes.

curl_retry() {
  local attempt=1
  local max_attempts=5
  local delay=${BUILDBOX_RETRY_DELAY:-2}
  local max_time=${BUILDBOX_CURL_TIMEOUT:-30}
  local status=0
  local out err previous_umask
  [[ "$delay" =~ ^[0-9]+([.][0-9]+)?$ ]] || delay=2
  [[ "$max_time" =~ ^[0-9]+([.][0-9]+)?$ ]] || max_time=30
  previous_umask=$(umask)
  umask 077
  out=$(mktemp)
  err=$(mktemp)
  umask "$previous_umask"

  while true; do
    : >"$out"
    : >"$err"
    set +e
    if command -v timeout >/dev/null 2>&1 && [[ "$max_time" != "0" ]]; then
      timeout "$max_time" curl "$@" >"$out" 2>"$err"
    else
      curl "$@" >"$out" 2>"$err"
    fi
    status=$?
    if [[ "$status" -eq 124 ]]; then
      status=28
      printf 'curl_retry: attempt timed out\n' >>"$err"
    fi
    set -e
    if [[ "$status" -eq 0 ]]; then
      cat "$out"
      cat "$err" >&2
      rm -f "$out" "$err"
      return 0
    fi
    cat "$err" >&2
    case "$status" in
      7 | 18 | 28 | 35 | 52 | 55 | 56)
        if [[ "$attempt" -ge "$max_attempts" ]]; then
          cat "$out"
          rm -f "$out" "$err"
          return "$status"
        fi
        sleep "$delay"
        attempt=$((attempt + 1))
        ;;
      *)
        cat "$out"
        rm -f "$out" "$err"
        return "$status"
        ;;
    esac
  done
}
