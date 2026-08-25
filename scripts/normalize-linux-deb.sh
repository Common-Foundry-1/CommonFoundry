#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C
export TZ=UTC
umask 022

PROJECT_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=release-linux-common.sh
source "$PROJECT_ROOT/scripts/release-linux-common.sh"

DEB_ARGUMENT="${1:?Pass the Tauri .deb path.}"
EXPECTED_COMMIT="$(cmfd_release_commit "${2:-}")"
EXPECTED_VERSION="${3:?Pass the expected package version.}"

cmfd_require_linux_glibc_x86_64
for command_name in cmp dpkg-deb find git gzip mktemp mv python3 realpath rm sed touch; do
  cmfd_require_command "$command_name"
done
for command_name in mktemp mv realpath rm touch; do
  if [[ "$("$command_name" --version | sed -n '1p')" != *'(GNU coreutils)'* ]]; then
    printf 'GNU coreutils %s is required.\n' "$command_name" >&2
    exit 1
  fi
done
FIND_VERSION="$(find --version | sed -n '1p')"
CMP_VERSION="$(cmp --version | sed -n '1p')"
if [[ "$FIND_VERSION" != *'(GNU findutils)'* || "$CMP_VERSION" != *'(GNU diffutils)'* ]]; then
  echo 'GNU findutils and diffutils are required.' >&2
  exit 1
fi
DPKG_DEB_VERSION="$(dpkg-deb --version | sed -n '1p')"
DPKG_DEB_HELP="$(dpkg-deb --help)"
for option in root-owner-group uniform-compression; do
  if ! grep -Fq -- "$option" <<<"$DPKG_DEB_HELP"; then
    printf 'dpkg-deb does not advertise required feature: %s\n' "$option" >&2
    exit 1
  fi
done
GZIP_VERSION="$(gzip --version | sed -n '1p')"

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

if [[ ! -f "$DEB_ARGUMENT" || -L "$DEB_ARGUMENT" ]]; then
  printf 'Expected a regular, non-symlink .deb: %s\n' "$DEB_ARGUMENT" >&2
  exit 1
fi
DEB_PATH="$(realpath -e -- "$DEB_ARGUMENT")"
TARGET_ROOT="$(realpath -e -- "$PROJECT_ROOT/target")"
if [[ "$DEB_PATH" != "$TARGET_ROOT/"* ]]; then
  printf 'The .deb must be inside the repository target directory: %s\n' "$DEB_PATH" >&2
  exit 1
fi
validate_identity() {
  local deb="$1"
  if [[ "$(dpkg-deb --field "$deb" Package)" != 'common-foundry-wallet' ||
    "$(dpkg-deb --field "$deb" Version)" != "$EXPECTED_VERSION" ||
    "$(dpkg-deb --field "$deb" Architecture)" != 'amd64' ]]; then
    echo 'The .deb package identity does not match Common Foundry, the expected version, and amd64.' >&2
    return 1
  fi
}
validate_identity "$DEB_PATH"
ORIGINAL_SEMANTIC="$(python3 "$PROJECT_ROOT/scripts/release_integrity.py" deb-inspect --deb "$DEB_PATH")"

SOURCE_DATE_EPOCH_VALUE="${SOURCE_DATE_EPOCH:-$(git -C "$PROJECT_ROOT" show -s --format=%ct "$EXPECTED_COMMIT")}"
if [[ ! "$SOURCE_DATE_EPOCH_VALUE" =~ ^[0-9]+$ ]]; then
  echo 'SOURCE_DATE_EPOCH must be a base-10 integer.' >&2
  exit 1
fi

TEMP_DIRECTORY="$(mktemp -d --tmpdir="$(dirname -- "$DEB_PATH")" .cmfd-deb-normalize.XXXXXX)"
trap 'rm -rf -- "$TEMP_DIRECTORY"' EXIT

validate_tree() {
  local root="$1"
  local unexpected
  unexpected="$(find -P "$root" -xdev ! -type f ! -type d -print -quit)"
  if [[ -n "$unexpected" ]]; then
    printf 'The .deb contains a symlink or special file: %s\n' "$unexpected" >&2
    return 1
  fi
  unexpected="$(find -P "$root" -xdev -type f -links +1 -print -quit)"
  if [[ -n "$unexpected" ]]; then
    printf 'The .deb contains a hard-linked file: %s\n' "$unexpected" >&2
    return 1
  fi
  if [[ ! -f "$root/DEBIAN/control" || -L "$root/DEBIAN/control" ]]; then
    echo 'The .deb does not contain a regular DEBIAN/control file.' >&2
    return 1
  fi
}

normalize_tree_times() {
  local root="$1"
  while IFS= read -r -d '' path; do
    touch --no-dereference --date="@$SOURCE_DATE_EPOCH_VALUE" -- "$path"
  done < <(find -P "$root" -xdev -depth -print0)
}

build_deb() {
  local root="$1"
  local output="$2"
  SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH_VALUE" dpkg-deb \
    --build \
    --root-owner-group \
    --uniform-compression \
    -Zgzip \
    -z9 \
    "$root" \
    "$output" >/dev/null
}

FIRST_ROOT="$TEMP_DIRECTORY/first-root"
FIRST_DEB="$TEMP_DIRECTORY/first.deb"
SECOND_ROOT="$TEMP_DIRECTORY/second-root"
SECOND_DEB="$TEMP_DIRECTORY/second.deb"

dpkg-deb --raw-extract "$DEB_PATH" "$FIRST_ROOT"
validate_tree "$FIRST_ROOT"
normalize_tree_times "$FIRST_ROOT"
build_deb "$FIRST_ROOT" "$FIRST_DEB"
validate_identity "$FIRST_DEB"
FIRST_SEMANTIC="$(python3 "$PROJECT_ROOT/scripts/release_integrity.py" deb-inspect --deb "$FIRST_DEB")"
if [[ "$FIRST_SEMANTIC" != "$ORIGINAL_SEMANTIC" ]]; then
  echo 'Normalized .deb changed the control or payload semantics.' >&2
  exit 1
fi

dpkg-deb --raw-extract "$FIRST_DEB" "$SECOND_ROOT"
validate_tree "$SECOND_ROOT"
normalize_tree_times "$SECOND_ROOT"
build_deb "$SECOND_ROOT" "$SECOND_DEB"
validate_identity "$SECOND_DEB"
SECOND_SEMANTIC="$(python3 "$PROJECT_ROOT/scripts/release_integrity.py" deb-inspect --deb "$SECOND_DEB")"
if [[ "$SECOND_SEMANTIC" != "$ORIGINAL_SEMANTIC" ]]; then
  echo 'Second-pass .deb changed the control or payload semantics.' >&2
  exit 1
fi
if ! cmp -s -- "$FIRST_DEB" "$SECOND_DEB"; then
  echo 'Normalized .deb is not byte-reproducible on a second pass.' >&2
  exit 1
fi

dpkg-deb --info "$FIRST_DEB" >/dev/null
dpkg-deb --contents "$FIRST_DEB" >/dev/null
mv -f -- "$FIRST_DEB" "$DEB_PATH"

printf 'Normalized package: %s\n' "$DEB_PATH"
printf 'SOURCE_DATE_EPOCH: %s\n' "$SOURCE_DATE_EPOCH_VALUE"
printf 'Semantic SHA-256: %s\n' "$ORIGINAL_SEMANTIC"
printf 'Toolchain: %s; %s; %s; %s\n' \
  "$DPKG_DEB_VERSION" \
  "$GZIP_VERSION" \
  "$FIND_VERSION" \
  "$(touch --version | sed -n '1p')"
