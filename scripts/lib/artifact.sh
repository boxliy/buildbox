#!/usr/bin/env bash
# Inspect the archive directory without extracting application artifacts.
artifact_signing_state() {
  "$(dirname "${BASH_SOURCE[0]}")/../dart-tool" artifact-state "$1"
}
