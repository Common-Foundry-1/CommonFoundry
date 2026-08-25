#!/usr/bin/env bash

cmfd_require_command() {
  local command_name="$1"
  if ! command -v "$command_name" >/dev/null 2>&1; then
    printf 'Required command is missing: %s\n' "$command_name" >&2
    return 1
  fi
}

cmfd_release_commit() {
  local supplied="${1:-${CMFD_RELEASE_COMMIT:-}}"
  if [[ ! "$supplied" =~ ^([0-9a-f]{40}|[0-9a-f]{64})$ ]]; then
    echo 'Pass the full lowercase release commit or set CMFD_RELEASE_COMMIT.' >&2
    return 1
  fi
  printf '%s\n' "$supplied"
}

cmfd_require_linux_glibc_x86_64() {
  local command_name
  for command_name in getconf uname; do
    cmfd_require_command "$command_name"
  done
  if [[ "$(uname -s)" != "Linux" || "$(uname -m)" != "x86_64" ]]; then
    echo 'This release package requires an x86_64 Linux build host.' >&2
    return 1
  fi
  if [[ "$(getconf GNU_LIBC_VERSION 2>/dev/null || true)" != glibc\ * ]]; then
    echo 'This release package requires a glibc build host.' >&2
    return 1
  fi
}

cmfd_require_linux_gnu_x86_64() {
  cmfd_require_linux_glibc_x86_64
  local command_name
  for command_name in awk file grep readelf rustc; do
    cmfd_require_command "$command_name"
  done
  local rust_host
  rust_host="$(rustc -vV | awk '/^host: / { print $2 }')"
  if [[ "$rust_host" != "x86_64-unknown-linux-gnu" ]]; then
    printf 'Rust host is %s; expected x86_64-unknown-linux-gnu.\n' "$rust_host" >&2
    return 1
  fi
}

cmfd_require_elf_x86_64() {
  local path="$1"
  local expected_kind="$2"
  if [[ ! -f "$path" || -L "$path" ]]; then
    printf 'Expected a regular, non-symlink ELF file: %s\n' "$path" >&2
    return 1
  fi
  local description
  description="$(LC_ALL=C file -Lb -- "$path")"
  if [[ "$description" != *'ELF 64-bit LSB'* || "$description" != *'x86-64'* ]]; then
    printf 'File is not an x86-64 ELF binary: %s (%s)\n' "$path" "$description" >&2
    return 1
  fi
  if ! LC_ALL=C readelf -h -- "$path" | grep -E 'Class:[[:space:]]+ELF64' >/dev/null; then
    printf 'ELF class is not ELF64: %s\n' "$path" >&2
    return 1
  fi
  if ! LC_ALL=C readelf -h -- "$path" | grep -E 'Machine:[[:space:]]+Advanced Micro Devices X86-64' >/dev/null; then
    printf 'ELF machine is not x86-64: %s\n' "$path" >&2
    return 1
  fi
  case "$expected_kind" in
    shared)
      if [[ "$description" != *'shared object'* ]] ||
        ! LC_ALL=C readelf -h -- "$path" | grep -E 'Type:[[:space:]]+DYN' >/dev/null; then
        printf 'ELF file is not a shared object: %s\n' "$path" >&2
        return 1
      fi
      ;;
    executable)
      if [[ "$description" != *'executable'* ]] ||
        ! LC_ALL=C readelf -h -- "$path" | grep -E 'Type:[[:space:]]+(EXEC|DYN)' >/dev/null; then
        printf 'ELF file is not an executable: %s\n' "$path" >&2
        return 1
      fi
      ;;
    *)
      printf 'Unknown ELF kind: %s\n' "$expected_kind" >&2
      return 1
      ;;
  esac
}
