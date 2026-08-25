#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C
export TZ=UTC
umask 022

PROJECT_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=release-linux-common.sh
source "$PROJECT_ROOT/scripts/release-linux-common.sh"

APPIMAGE_ARGUMENT="${1:?Pass the Tauri AppImage path.}"
EXPECTED_COMMIT="$(cmfd_release_commit "${2:-}")"
EXPECTED_VERSION="${3:?Pass the expected package version.}"
CACHE_ROOT="${XDG_CACHE_HOME:-${HOME:?HOME must be set.}/.cache}"
TAURI_APPIMAGE_PLUGIN="$CACHE_ROOT/tauri/linuxdeploy-plugin-appimage.AppImage"
TAURI_APPIMAGE_PLUGIN_SHA256='a45d3e227bc7f397e9cf6bfa4c9507494efa2293357b6e86690a3de2ca992e79'

cmfd_require_linux_glibc_x86_64
for command_name in chmod cmp cp env find git grep id mktemp mv python3 realpath rm sed sha256sum stat touch unsquashfs; do
  cmfd_require_command "$command_name"
done
for command_name in chmod cp mktemp mv realpath rm sha256sum stat touch; do
  if [[ "$("$command_name" --version | sed -n '1p')" != *'(GNU coreutils)'* ]]; then
    printf 'GNU coreutils %s is required.\n' "$command_name" >&2
    exit 1
  fi
done
FIND_VERSION="$(find --version | sed -n '1p')"
CMP_VERSION="$(cmp --version | sed -n '1p')"
UNSQUASHFS_VERSION="$(unsquashfs -version 2>&1 | sed -n '1p' || true)"
if [[ "$FIND_VERSION" != *'(GNU findutils)'* || "$CMP_VERSION" != *'(GNU diffutils)'* ]]; then
  echo 'GNU findutils and diffutils are required.' >&2
  exit 1
fi
if [[ "$UNSQUASHFS_VERSION" != 'unsquashfs version '* ]]; then
  echo 'A recognized unsquashfs implementation is required.' >&2
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
  echo 'Repository must be clean before normalizing a release package.' >&2
  exit 1
fi

if [[ ! -f "$APPIMAGE_ARGUMENT" || -L "$APPIMAGE_ARGUMENT" || ! -x "$APPIMAGE_ARGUMENT" ]]; then
  printf 'Expected an executable, regular, non-symlink AppImage: %s\n' "$APPIMAGE_ARGUMENT" >&2
  exit 1
fi
APPIMAGE_PATH="$(realpath -e -- "$APPIMAGE_ARGUMENT")"
TARGET_ROOT="$(realpath -e -- "$PROJECT_ROOT/target")"
if [[ "$APPIMAGE_PATH" != "$TARGET_ROOT/"* ]]; then
  printf 'The AppImage must be inside the repository target directory: %s\n' "$APPIMAGE_PATH" >&2
  exit 1
fi

if [[ ! -f "$TAURI_APPIMAGE_PLUGIN" || -L "$TAURI_APPIMAGE_PLUGIN" || ! -x "$TAURI_APPIMAGE_PLUGIN" ]]; then
  printf 'Expected Tauri AppImage plugin at %s.\n' "$TAURI_APPIMAGE_PLUGIN" >&2
  exit 1
fi
read -r ACTUAL_PLUGIN_SHA256 _ < <(sha256sum -- "$TAURI_APPIMAGE_PLUGIN")
if [[ "$ACTUAL_PLUGIN_SHA256" != "$TAURI_APPIMAGE_PLUGIN_SHA256" ]]; then
  printf 'Tauri AppImage plugin digest is %s; expected %s.\n' \
    "$ACTUAL_PLUGIN_SHA256" \
    "$TAURI_APPIMAGE_PLUGIN_SHA256" >&2
  exit 1
fi

SOURCE_DATE_EPOCH_VALUE="${SOURCE_DATE_EPOCH:-$(git -C "$PROJECT_ROOT" show -s --format=%ct "$EXPECTED_COMMIT")}"
if [[ ! "$SOURCE_DATE_EPOCH_VALUE" =~ ^[0-9]+$ ]]; then
  echo 'SOURCE_DATE_EPOCH must be a base-10 integer.' >&2
  exit 1
fi

TEMP_DIRECTORY="$(mktemp -d --tmpdir="$(dirname -- "$APPIMAGE_PATH")" .cmfd-appimage-normalize.XXXXXX)"
chmod 0755 "$TEMP_DIRECTORY"
trap 'rm -rf -- "$TEMP_DIRECTORY"' EXIT

validate_tree_shape() {
  local root="$1"
  local unexpected
  unexpected="$(find -P "$root" -xdev ! -type f ! -type d ! -type l -print -quit)"
  if [[ -n "$unexpected" ]]; then
    printf 'The AppImage contains a special file: %s\n' "$unexpected" >&2
    return 1
  fi
  unexpected="$(find -P "$root" -xdev -type f -links +1 -print -quit)"
  if [[ -n "$unexpected" ]]; then
    printf 'The AppImage contains a hard-linked file: %s\n' "$unexpected" >&2
    return 1
  fi
  for required_path in \
    "$root/AppRun" \
    "$root/AppRun.wrapped" \
    "$root/usr/bin/common-foundry-wallet" \
    "$root/usr/share/applications/Common Foundry Wallet.desktop"; do
    if [[ ! -f "$required_path" || -L "$required_path" ]]; then
      printf 'The AppImage is missing a required regular file: %s\n' "$required_path" >&2
      return 1
    fi
  done
}

write_semantic_manifest() {
  local root="$1"
  local output="$2"
  python3 - "$root" "$output" <<'PY'
import hashlib
import json
import os
import pathlib
import posixpath
import stat
import sys

root = pathlib.Path(sys.argv[1])
output = pathlib.Path(sys.argv[2])
entries = []
seen_regular = set()


def visit(directory: pathlib.Path, prefix: str) -> None:
    with os.scandir(directory) as iterator:
        children = sorted(iterator, key=lambda entry: entry.name)
    for entry in children:
        relative = f"{prefix}/{entry.name}" if prefix else entry.name
        metadata = entry.stat(follow_symlinks=False)
        mode = metadata.st_mode
        if stat.S_ISDIR(mode):
            entries.append(
                {
                    "mode": format(stat.S_IMODE(mode), "04o"),
                    "path": relative,
                    "type": "directory",
                }
            )
            visit(pathlib.Path(entry.path), relative)
        elif stat.S_ISREG(mode):
            identity = (metadata.st_dev, metadata.st_ino)
            if identity in seen_regular:
                raise SystemExit(f"hard-linked file is not allowed: {relative}")
            seen_regular.add(identity)
            digest = hashlib.sha256()
            with open(entry.path, "rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(chunk)
            entries.append(
                {
                    "path": relative,
                    "mode": format(stat.S_IMODE(mode), "04o"),
                    "type": "file",
                    "size": metadata.st_size,
                    "sha256": digest.hexdigest(),
                }
            )
        elif stat.S_ISLNK(mode):
            target = os.readlink(entry.path)
            if posixpath.isabs(target):
                raise SystemExit(f"absolute symlink is not allowed: {relative} -> {target}")
            resolved = posixpath.normpath(posixpath.join(posixpath.dirname(relative), target))
            if resolved == ".." or resolved.startswith("../"):
                raise SystemExit(f"escaping symlink is not allowed: {relative} -> {target}")
            entries.append({"path": relative, "type": "symlink", "target": target})
        else:
            raise SystemExit(f"special file is not allowed: {relative}")


visit(root, "")
with output.open("w", encoding="utf-8", newline="\n") as handle:
    json.dump(entries, handle, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
    handle.write("\n")
PY
}

normalize_tree() {
  local root="$1"
  find -P "$root" -xdev ! -type l -exec chmod a-s,go-w -- {} +
  chmod 0755 \
    "$root/AppRun" \
    "$root/AppRun.wrapped" \
    "$root/usr/bin/common-foundry-wallet"
  chmod 0644 "$root/usr/share/applications/Common Foundry Wallet.desktop"
  while IFS= read -r -d '' path; do
    touch --no-dereference --date="@$SOURCE_DATE_EPOCH_VALUE" -- "$path"
  done < <(find -P "$root" -xdev -depth -print0)
}

validate_normalized_tree() {
  local root="$1"
  local unexpected
  validate_tree_shape "$root"
  unexpected="$(find -P "$root" -xdev ! -type l -perm /022 -print -quit)"
  if [[ -n "$unexpected" ]]; then
    printf 'The normalized AppImage contains a group/world-writable path: %s\n' "$unexpected" >&2
    return 1
  fi
  unexpected="$(find -P "$root" -xdev ! -type l -perm /6000 -print -quit)"
  if [[ -n "$unexpected" ]]; then
    printf 'The normalized AppImage contains a setuid/setgid path: %s\n' "$unexpected" >&2
    return 1
  fi
  if [[ "$(stat -c '%a' "$root/AppRun")" != '755' ||
    "$(stat -c '%a' "$root/AppRun.wrapped")" != '755' ||
    "$(stat -c '%a' "$root/usr/bin/common-foundry-wallet")" != '755' ||
    "$(stat -c '%a' "$root/usr/share/applications/Common Foundry Wallet.desktop")" != '644' ]]; then
    echo 'The normalized AppImage entrypoint or desktop-file modes are incorrect.' >&2
    return 1
  fi
}

extract_appimage() {
  local image="$1"
  local root="$2"
  local offset
  offset="$("$image" --appimage-offset)"
  if [[ ! "$offset" =~ ^[0-9]+$ || "$offset" == '0' ]]; then
    printf 'Invalid AppImage SquashFS offset: %s\n' "$offset" >&2
    return 1
  fi
  unsquashfs -no-progress -o "$offset" -d "$root" "$image" >/dev/null
}

build_appimage() {
  local root="$1"
  local output="$2"
  local log="$3"
  (
    cd -- "$TEMP_DIRECTORY"
    ARCH=x86_64 \
      APPIMAGE_EXTRACT_AND_RUN=1 \
      OUTPUT="$output" \
      SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH_VALUE" \
      "$TAURI_APPIMAGE_PLUGIN" --appdir="$root" >"$log" 2>&1
  )
  if [[ ! -s "$output" || -L "$output" ]]; then
    printf 'Tauri did not produce a regular AppImage: %s\n' "$output" >&2
    return 1
  fi
  chmod 0755 "$output"
}

run_unprivileged() {
  cmfd_require_command setpriv
  if [[ "$(id -u)" == '0' ]]; then
    setpriv --reuid=65534 --regid=65534 --clear-groups --no-new-privs "$@"
  else
    setpriv --no-new-privs "$@"
  fi
}

verify_entrypoints() {
  local root="$1"
  local appimage="$2"
  local entrypoint
  for entrypoint in \
    "$root/AppRun.wrapped" \
    "$root/AppRun" \
    "$root/usr/bin/common-foundry-wallet"; do
    if [[ "$(run_unprivileged "$entrypoint" --version)" != "$EXPECTED_VERSION" ]]; then
      printf 'Unprivileged version check failed: %s\n' "$entrypoint" >&2
      return 1
    fi
  done
  if [[ "$(run_unprivileged env APPIMAGE_EXTRACT_AND_RUN=1 "$appimage" --version)" != "$EXPECTED_VERSION" ]]; then
    printf 'Unprivileged outer AppImage version check failed: %s\n' "$appimage" >&2
    return 1
  fi
}

FIRST_ROOT="$TEMP_DIRECTORY/first-root"
FIRST_MANIFEST="$TEMP_DIRECTORY/first-semantic.json"
FIRST_APPIMAGE="$TEMP_DIRECTORY/first.AppImage"
SECOND_ROOT="$TEMP_DIRECTORY/second-root"
SECOND_MANIFEST="$TEMP_DIRECTORY/second-semantic.json"
SECOND_APPIMAGE="$TEMP_DIRECTORY/second.AppImage"

extract_appimage "$APPIMAGE_PATH" "$FIRST_ROOT"
validate_tree_shape "$FIRST_ROOT"
normalize_tree "$FIRST_ROOT"
validate_normalized_tree "$FIRST_ROOT"
write_semantic_manifest "$FIRST_ROOT" "$FIRST_MANIFEST"
build_appimage "$FIRST_ROOT" "$FIRST_APPIMAGE" "$TEMP_DIRECTORY/first-build.log"

extract_appimage "$FIRST_APPIMAGE" "$SECOND_ROOT"
validate_normalized_tree "$SECOND_ROOT"
write_semantic_manifest "$SECOND_ROOT" "$SECOND_MANIFEST"
if ! cmp -s -- "$FIRST_MANIFEST" "$SECOND_MANIFEST"; then
  echo 'Normalized AppImage changed the payload inventory, content, modes, or symlink targets.' >&2
  exit 1
fi
verify_entrypoints "$SECOND_ROOT" "$FIRST_APPIMAGE"

normalize_tree "$SECOND_ROOT"
build_appimage "$SECOND_ROOT" "$SECOND_APPIMAGE" "$TEMP_DIRECTORY/second-build.log"
if ! cmp -s -- "$FIRST_APPIMAGE" "$SECOND_APPIMAGE"; then
  echo 'Normalized AppImage is not byte-reproducible on a second pass.' >&2
  exit 1
fi

read -r APPIMAGE_SHA256 _ < <(sha256sum -- "$FIRST_APPIMAGE")
mv -f -- "$FIRST_APPIMAGE" "$APPIMAGE_PATH"

printf 'Normalized AppImage: %s\n' "$APPIMAGE_PATH"
printf 'SOURCE_DATE_EPOCH: %s\n' "$SOURCE_DATE_EPOCH_VALUE"
printf 'SHA-256: %s\n' "$APPIMAGE_SHA256"
printf 'Tauri AppImage plugin SHA-256: %s\n' "$ACTUAL_PLUGIN_SHA256"
printf 'Toolchain: %s; %s; %s\n' "$UNSQUASHFS_VERSION" "$FIND_VERSION" "$(touch --version | sed -n '1p')"
