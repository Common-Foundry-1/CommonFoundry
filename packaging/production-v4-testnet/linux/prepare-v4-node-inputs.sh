#!/usr/bin/env bash
set -euo pipefail
umask 077

SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
DESTINATION="${1:-$SCRIPT_DIR/production-v4}"
RELEASE_BASE="${CMFD_RELEASE_BASE:-https://github.com/JustAResearcher/CommonFoundry-Binaries/releases/download/v0.1.0-devnet.16}"
PART_DIRECTORY="$DESTINATION/.parts"
OUTPUT="$DESTINATION/MODEL-V2.bank"
PART_NAMES=(
  V4-MODEL-V2.bank.part01
  V4-MODEL-V2.bank.part02
  V4-MODEL-V2.bank.part03
  V4-MODEL-V2.bank.part04
)
PART_HASHES=(
  3af0fd15bf0377bab42f2c59d8337f4f82e87e32c5f8c4f27ebfc21681450254
  9d4f2547dc632c1c5f74ace84d26ca2ce38be50bea01ed93542fc5ab56aed6cf
  a1bf1ac3230a54006039b3ce2add912e4c6f94065afad322bbaebee15b089602
  5af1c6de16f5d48032aa9b37a5d48abd5d6c6e22b24935476faddb9af2cf7069
)
OUTPUT_BYTES=6442975416
OUTPUT_HASH=5f9b213c3bda51b74e4ebabb26607b67385d613aa8d99af915a48ab063e17d4e

verify() {
  local path="$1" bytes="$2" hash="$3"
  [[ -f "$path" ]] || return 1
  [[ "$(wc -c < "$path")" -eq "$bytes" ]] || return 1
  printf '%s  %s\n' "$hash" "$path" | sha256sum --check --status
}

mkdir -p -- "$PART_DIRECTORY"
if ! verify "$OUTPUT" "$OUTPUT_BYTES" "$OUTPUT_HASH"; then
  for index in "${!PART_NAMES[@]}"; do
    name="${PART_NAMES[$index]}"
    part="$PART_DIRECTORY/$name"
    if ! printf '%s  %s\n' "${PART_HASHES[$index]}" "$part" | sha256sum --check --status 2>/dev/null; then
      download="$part.download"
      rm -f -- "$download"
      echo "Downloading $name"
      curl --fail --location --retry 3 --output "$download" "$RELEASE_BASE/$name"
      printf '%s  %s\n' "${PART_HASHES[$index]}" "$download" | sha256sum --check --status
      mv -f -- "$download" "$part"
    fi
  done

  partial="$OUTPUT.partial"
  rm -f -- "$partial"
  for name in "${PART_NAMES[@]}"; do
    cat -- "$PART_DIRECTORY/$name" >> "$partial"
  done
  verify "$partial" "$OUTPUT_BYTES" "$OUTPUT_HASH"
  mv -f -- "$partial" "$OUTPUT"
  for name in "${PART_NAMES[@]}"; do
    rm -f -- "$PART_DIRECTORY/$name"
  done
fi

cp -f -- "$SCRIPT_DIR/FORGEMATRIX-V4-FIXED-ARTIFACT-RECORD-V1.json" \
  "$DESTINATION/FORGEMATRIX-V4-FIXED-ARTIFACT-RECORD-V1.json"
echo "ProductionV4 node inputs are authenticated under $DESTINATION"
