#!/usr/bin/env bash
set -euo pipefail

PACKAGE_NAME="${1:-}"
SECRET="${2:-TRANSFERCHAIN_TAMPER_TEST_SECRET}"

if [[ -z "$PACKAGE_NAME" ]]; then
  echo "Usage: $0 <package.name> [secret]"
  exit 1
fi

TMP_FILE="$(mktemp)"
trap 'rm -f "$TMP_FILE"' EXIT

adb shell run-as "$PACKAGE_NAME" \
  cat shared_prefs/transferchain_secure_storage_v1.xml \
  > "$TMP_FILE"

if grep -Fq "$SECRET" "$TMP_FILE"; then
  echo "FAIL: Plaintext secret found in SharedPreferences."
  exit 2
fi

echo "PASS: Plaintext secret not found in SharedPreferences."
