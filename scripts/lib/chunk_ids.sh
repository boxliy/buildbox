#!/usr/bin/env bash
# Shared chunk membership rules for prepare and the independent finalizer.
# Caller defines die() and exports BUILDBOX_RUN_ID. BUILD_RUN_IDS is optional.
# Sets CHUNK_IDS.

chunk_ids() {
  local raw id
  CHUNK_IDS=()
  [[ -n "${BUILDBOX_RUN_ID:-}" ]] || die 'BUILDBOX_RUN_ID is required'
  [[ "$BUILDBOX_RUN_ID" =~ ^[0-9]+$ ]] || die 'BUILDBOX_RUN_ID must be a platform run id'
  if [[ -n "${BUILD_RUN_IDS:-}" ]]; then
    local raw_ids=()
    IFS=',' read -r -a raw_ids <<<"$BUILD_RUN_IDS"
    for raw in "${raw_ids[@]}"; do
      id=${raw//[[:space:]]/}
      [[ -n "$id" ]] || continue
      [[ "$id" =~ ^[0-9]+$ ]] || die "illegal run id: $id"
      CHUNK_IDS+=("$id")
    done
  else
    CHUNK_IDS=("$BUILDBOX_RUN_ID")
  fi
  [[ ${#CHUNK_IDS[@]} -ge 1 ]] || die 'missing run id'
  [[ ${#CHUNK_IDS[@]} -le 20 ]] || die 'a chunk can contain at most 20 runs'
  [[ "${CHUNK_IDS[0]}" == "$BUILDBOX_RUN_ID" ]] || die 'the first chunk run must be the dispatched build_run_id'
}
