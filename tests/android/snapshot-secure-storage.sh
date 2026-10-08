#!/usr/bin/env bash
set -euo pipefail

PACKAGE_NAME="${1:-}"
OUTPUT_FILE="${2:-secure-storage-snapshot.xml}"

if [[ -z "$PACKAGE_NAME" ]]; then
  echo "Usage: $0 <package.name> [output-file]"
  exit 1
fi

adb shell run-as "$PACKAGE_NAME" \
  cat shared_prefs/transferchain_secure_storage_v1.xml \
  > "$OUTPUT_FILE"

echo "Snapshot written to: $OUTPUT_FILE"
