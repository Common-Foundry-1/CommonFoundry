#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C
export TZ=UTC
umask 022

PROJECT_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=release-linux-common.sh
source "$PROJECT_ROOT/scripts/release-linux-common.sh"

EXPECTED_COMMIT="$(cmfd_release_commit "${1:-}")"
MODE="${2:-prepare}"
if [[ "$MODE" != 'prepare' && "$MODE" != 'verify' ]]; then
  echo 'Mode must be prepare or verify.' >&2
  exit 1
fi

cmfd_require_linux_glibc_x86_64
for command_name in chmod curl dd git mkdir mktemp mv realpath rm sed sha256sum stat; do
  cmfd_require_command "$command_name"
done
for command_name in chmod mkdir mktemp mv realpath rm sha256sum stat; do
  if [[ "$("$command_name" --version | sed -n '1p')" != *'(GNU coreutils)'* ]]; then
    printf 'GNU coreutils %s is required.\n' "$command_name" >&2
    exit 1
  fi
done
DD_VERSION="$(dd --version | sed -n '1p')"
if [[ "$DD_VERSION" != *'(coreutils)'* ]]; then
  echo 'GNU coreutils dd is required.' >&2
  exit 1
fi

ACTUAL_COMMIT="$(git -C "$PROJECT_ROOT" rev-parse HEAD)"
if [[ "$ACTUAL_COMMIT" != "$EXPECTED_COMMIT" ]]; then
  printf 'Repository HEAD is %s; expected %s.\n' "$ACTUAL_COMMIT" "$EXPECTED_COMMIT" >&2
  exit 1
fi
if ! git -C "$PROJECT_ROOT" diff --quiet -- ||
  ! git -C "$PROJECT_ROOT" diff --cached --quiet -- ||
  [[ -n "$(git -C "$PROJECT_ROOT" ls-files --others --exclude-standard)" ]]; then
  echo 'Repository must be clean before preparing release tooling.' >&2
  exit 1
fi

CACHE_ROOT="${XDG_CACHE_HOME:-${HOME:?HOME must be set.}/.cache}"
if [[ "$CACHE_ROOT" != /* ]]; then
  printf 'The Tauri cache root must be absolute: %s\n' "$CACHE_ROOT" >&2
  exit 1
fi
TOOLS_DIRECTORY="$CACHE_ROOT/tauri"
if [[ -L "$TOOLS_DIRECTORY" || ( -e "$TOOLS_DIRECTORY" && ! -d "$TOOLS_DIRECTORY" ) ]]; then
  printf 'The Tauri tools path must be a real directory: %s\n' "$TOOLS_DIRECTORY" >&2
  exit 1
fi
mkdir -p -- "$TOOLS_DIRECTORY"
TOOLS_DIRECTORY="$(realpath -e -- "$TOOLS_DIRECTORY")"
TEMP_DIRECTORY="$(mktemp -d --tmpdir="$TOOLS_DIRECTORY" .cmfd-tauri-tools.XXXXXX)"
chmod 0700 "$TEMP_DIRECTORY"
trap 'rm -rf -- "$TEMP_DIRECTORY"' EXIT

verify_digest() {
  local path="$1"
  local expected="$2"
  local actual
  read -r actual _ < <(sha256sum -- "$path")
  [[ "$actual" == "$expected" ]]
}

prepare_tool() {
  local filename="$1"
  local url="$2"
  local expected_sha256="$3"
  local patch_linuxdeploy="$4"
  local destination="$TOOLS_DIRECTORY/$filename"

  if [[ -L "$destination" || ( -e "$destination" && ! -f "$destination" ) ]]; then
    printf 'Tauri tool path must be a regular, non-symlink file: %s\n' "$destination" >&2
    return 1
  fi
  if [[ -f "$destination" ]] && verify_digest "$destination" "$expected_sha256"; then
    if [[ "$MODE" == 'verify' && "$(stat -c '%a' "$destination")" != '755' ]]; then
      printf 'Pinned Tauri tool has mode %s; expected 755: %s\n' \
        "$(stat -c '%a' "$destination")" \
        "$destination" >&2
      return 1
    fi
    if [[ "$MODE" == 'prepare' ]]; then
      chmod 0755 "$destination"
    fi
    printf 'Verified Tauri tool: %s (%s)\n' "$filename" "$expected_sha256"
    return 0
  fi
  if [[ "$MODE" == 'verify' ]]; then
    printf 'Tauri tool is missing or has the wrong digest: %s\n' "$destination" >&2
    return 1
  fi

  local temporary="$TEMP_DIRECTORY/$filename"
  curl \
    --fail \
    --location \
    --proto '=https' \
    --retry 3 \
    --retry-all-errors \
    --show-error \
    --silent \
    --tlsv1.2 \
    --output "$temporary" \
    "$url"
  if [[ "$patch_linuxdeploy" == 'yes' ]]; then
    dd if=/dev/zero bs=1 count=3 seek=8 conv=notrunc status=none of="$temporary"
  fi
  if ! verify_digest "$temporary" "$expected_sha256"; then
    local actual
    read -r actual _ < <(sha256sum -- "$temporary")
    printf 'Downloaded Tauri tool %s has digest %s; expected %s.\n' \
      "$filename" \
      "$actual" \
      "$expected_sha256" >&2
    return 1
  fi
  chmod 0755 "$temporary"
  mv -f -- "$temporary" "$destination"
  printf 'Installed pinned Tauri tool: %s (%s)\n' "$filename" "$expected_sha256"
}

prepare_tool \
  'AppRun-x86_64' \
  'https://github.com/tauri-apps/binary-releases/releases/download/apprun-old/AppRun-x86_64' \
  'f30140a43a0a59e46db21bdefdf749b9e9f2c6946e92afabbacf98b8ae73fb4f' \
  'no'
prepare_tool \
  'linuxdeploy-x86_64.AppImage' \
  'https://github.com/tauri-apps/binary-releases/releases/download/linuxdeploy/linuxdeploy-x86_64.AppImage' \
  '20eebde3c18ae2e44279bd624fc72482503aece216d5d77f10932235342f71c1' \
  'yes'
prepare_tool \
  'linuxdeploy-plugin-gtk.sh' \
  'https://raw.githubusercontent.com/tauri-apps/linuxdeploy-plugin-gtk/b5eb8d05b4c0ed40107fe2158c5d8527f94568ef/linuxdeploy-plugin-gtk.sh' \
  'cb379f9b0733e9ad9f8bd78f8c2fa038aef2478523bb7d4c8e64ff6a1ea3501a' \
  'no'
prepare_tool \
  'linuxdeploy-plugin-gstreamer.sh' \
  'https://raw.githubusercontent.com/tauri-apps/linuxdeploy-plugin-gstreamer/2a2e67491c32995a3f279ad0ecbe77abd512b42a/linuxdeploy-plugin-gstreamer.sh' \
  'c107b49d84edbffc6ab226ed1007e0626a4f7aa2c3a36b7782bef62351d49e94' \
  'no'
prepare_tool \
  'linuxdeploy-plugin-appimage.AppImage' \
  'https://github.com/linuxdeploy/linuxdeploy-plugin-appimage/releases/download/continuous/linuxdeploy-plugin-appimage-x86_64.AppImage' \
  'a45d3e227bc7f397e9cf6bfa4c9507494efa2293357b6e86690a3de2ca992e79' \
  'no'

printf 'Pinned Tauri AppImage tools: %s (%s)\n' "$TOOLS_DIRECTORY" "$MODE"
