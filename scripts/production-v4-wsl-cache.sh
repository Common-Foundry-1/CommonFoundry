#!/usr/bin/env bash
set -euo pipefail

command_name="${1:-}"
if [[ -z "$command_name" ]]; then
  echo "missing WSL cache command" >&2
  exit 2
fi
shift

cache_state() {
  local destination="$1"
  local expected_bytes="$2"
  local expected_sha="$3"
  local marker="${destination}.verified"
  if [[ -f "$destination" && "$(stat -c %s -- "$destination")" == "$expected_bytes" &&
        -f "$marker" && "$(<"$marker")" == "$expected_sha" ]]; then
    echo cached
  else
    echo missing
  fi
}

require_owned_path() {
  local root="$1"
  local target="$2"
  local prefix="$3"
  if [[ -z "$root" || -z "$prefix" || "$target" != "$root/$prefix"* ]]; then
    echo "refusing unsafe WSL directory operation: $target" >&2
    exit 2
  fi
}

case "$command_name" in
  cache-root)
    printf '%s\n' "${XDG_CACHE_HOME:-$HOME/.cache}/commonfoundry/production-v4"
    ;;
  scratch-root)
    available_bytes="$(df -PB1 /dev/shm | awk 'NR == 2 { print $4 }')"
    if [[ "$available_bytes" =~ ^[0-9]+$ && "$available_bytes" -ge 3221225472 ]]; then
      echo /dev/shm/commonfoundry-production-v4
    else
      printf '%s\n' "${XDG_CACHE_HOME:-$HOME/.cache}/commonfoundry/production-v4/work"
    fi
    ;;
  cache-state)
    cache_state "$@"
    ;;
  cache-file)
    source_path="$1"
    destination="$2"
    expected_bytes="$3"
    expected_sha="$4"
    if [[ "$(cache_state "$destination" "$expected_bytes" "$expected_sha")" == cached ]]; then
      echo cached
      exit 0
    fi
    mkdir -p -- "$(dirname -- "$destination")"
    temporary="${destination}.tmp.$$"
    marker="${destination}.verified"
    temporary_marker="${marker}.tmp.$$"
    trap 'rm -f -- "$temporary" "$temporary_marker"' EXIT
    cp -- "$source_path" "$temporary"
    [[ "$(stat -c %s -- "$temporary")" == "$expected_bytes" ]]
    [[ "$(sha256sum -- "$temporary" | cut -d ' ' -f 1)" == "$expected_sha" ]]
    chmod 0444 -- "$temporary"
    printf '%s\n' "$expected_sha" >"$temporary_marker"
    mv -f -- "$temporary" "$destination"
    mv -f -- "$temporary_marker" "$marker"
    trap - EXIT
    echo populated
    ;;
  fixed-view)
    destination="$1"
    record="$2"
    shift 2
    mkdir -p -- "$destination"
    cp -f -- "$record" "$destination/FORGEMATRIX-V4-FIXED-ARTIFACT-RECORD-V1.json"
    for bank in 0 1 2; do
      tree="$1"
      row_major="$2"
      shift 2
      ln -sfn -- "$tree" "$destination/FORGEMATRIX-V4-FIXED-BANK-${bank}.tree"
      ln -sfn -- "$row_major" "$destination/FORGEMATRIX-V4-FIXED-BANK-${bank}.row-major.codeword"
    done
    ;;
  make-owned)
    require_owned_path "$1" "$2" "$3"
    mkdir -p -- "$2"
    ;;
  preserve-attempt)
    source_directory="$1"
    destination="$2"
    for path in "$source_directory"/trace-* "$source_directory"/dynamic-commitments.json; do
      if [[ -e "$path" ]]; then
        cp -- "$path" "$destination/"
      fi
    done
    ;;
  remove-owned)
    require_owned_path "$1" "$2" "$3"
    rm -rf -- "$2"
    ;;
  *)
    echo "unknown WSL cache command: $command_name" >&2
    exit 2
    ;;
esac
