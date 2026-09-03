#!/usr/bin/env bash
set -euo pipefail
umask 077

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
DESTINATION="${1:-$SCRIPT_DIR/production-v4}"
RELEASE_BASES=(
  "${CMFD_RELEASE_BASE:-https://downloads.commonfoundry.ai/v0.1.0-rc.1}"
  "${CMFD_FALLBACK_RELEASE_BASE:-https://github.com/JustAResearcher/CommonFoundry-Binaries/releases/download/v0.1.0-rc.1}"
)
PART_DIRECTORY="$DESTINATION/.parts"
OUTPUT="$DESTINATION/MODEL-V2.bank"
PART_NAMES=(V4-MODEL-V2.bank.part01 V4-MODEL-V2.bank.part02 V4-MODEL-V2.bank.part03 V4-MODEL-V2.bank.part04)
PART_BYTES=(1610743854 1610743854 1610743854 1610743854)
PART_HASHES=(
  3af0fd15bf0377bab42f2c59d8337f4f82e87e32c5f8c4f27ebfc21681450254
  9d4f2547dc632c1c5f74ace84d26ca2ce38be50bea01ed93542fc5ab56aed6cf
  a1bf1ac3230a54006039b3ce2add912e4c6f94065afad322bbaebee15b089602
  5af1c6de16f5d48032aa9b37a5d48abd5d6c6e22b24935476faddb9af2cf7069
)
OUTPUT_BYTES=6442975416
OUTPUT_HASH=5f9b213c3bda51b74e4ebabb26607b67385d613aa8d99af915a48ab063e17d4e
FIXED_RECORD=FORGEMATRIX-V4-FIXED-ARTIFACT-RECORD-V1.json
FIXED_BYTES=6973
FIXED_HASH=ea218831aa567e486426ded77c84a5752a817329c496e3557c6d43577f0afe79

verify() {
  local path="$1" bytes="$2" hash="$3"
  [[ -f "$path" ]] || return 1
  [[ "$(wc -c < "$path")" -eq "$bytes" ]] || return 1
  printf '%s  %s\n' "$hash" "$path" | sha256sum --check --status
}

download_part() {
  local index="$1" name part download bytes downloaded downloaded_ok
  name="${PART_NAMES[$index]}"
  part="$PART_DIRECTORY/$name"
  bytes="${PART_BYTES[$index]}"
  verify "$part" "$bytes" "${PART_HASHES[$index]}" && return 0
  download="$part.download"
  if [[ -f "$download" ]]; then
    downloaded="$(wc -c < "$download")"
    if [[ "$downloaded" -gt "$bytes" ]] ||
       { [[ "$downloaded" -eq "$bytes" ]] && ! verify "$download" "$bytes" "${PART_HASHES[$index]}"; }; then
      rm -f -- "$download"
    fi
  fi
  downloaded=0
  [[ ! -f "$download" ]] || downloaded="$(wc -c < "$download")"
  echo "Downloading $name ($downloaded of $bytes bytes already present)"
  downloaded_ok=0
  for release_base in "${RELEASE_BASES[@]}"; do
    if curl --fail --location --silent --show-error --retry 5 --retry-delay 3 \
      --connect-timeout 30 --speed-limit 1024 --speed-time 30 --continue-at - \
      --output "$download" "$release_base/$name"; then
      downloaded_ok=1
      break
    fi
  done
  [[ "$downloaded_ok" -eq 1 ]] || { echo "ERROR: all download sources failed for $name" >&2; return 1; }
  verify "$download" "$bytes" "${PART_HASHES[$index]}"
  mv -f -- "$download" "$part"
  echo "Authenticated $name"
}

for command_name in curl sha256sum; do
  command -v "$command_name" >/dev/null 2>&1 || { echo "ERROR: $command_name is required." >&2; exit 1; }
done
mkdir -p -- "$DESTINATION" "$PART_DIRECTORY"
if ! verify "$OUTPUT" "$OUTPUT_BYTES" "$OUTPUT_HASH"; then
  pids=()
  for index in "${!PART_NAMES[@]}"; do download_part "$index" & pids+=("$!"); done
  failed=0
  for pid in "${pids[@]}"; do wait "$pid" || failed=1; done
  [[ "$failed" -eq 0 ]] || { echo 'ERROR: one or more RCNet-1 model-bank parts failed.' >&2; exit 1; }
  partial="$OUTPUT.partial"
  rm -f -- "$partial"
  for name in "${PART_NAMES[@]}"; do cat -- "$PART_DIRECTORY/$name" >> "$partial"; done
  verify "$partial" "$OUTPUT_BYTES" "$OUTPUT_HASH"
  mv -f -- "$partial" "$OUTPUT"
  for name in "${PART_NAMES[@]}"; do rm -f -- "$PART_DIRECTORY/$name"; done
fi
verify "$SCRIPT_DIR/$FIXED_RECORD" "$FIXED_BYTES" "$FIXED_HASH" || { echo 'ERROR: bundled RCNet-1 fixed record failed authentication.' >&2; exit 1; }
mkdir -p -- "$DESTINATION"
if ! verify "$DESTINATION/$FIXED_RECORD" "$FIXED_BYTES" "$FIXED_HASH"; then
  cp -f -- "$SCRIPT_DIR/$FIXED_RECORD" "$DESTINATION/$FIXED_RECORD"
fi
verify "$DESTINATION/$FIXED_RECORD" "$FIXED_BYTES" "$FIXED_HASH"
echo "Authenticated RCNet-1 wallet runtime under $DESTINATION"
