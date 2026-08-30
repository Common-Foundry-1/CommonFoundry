#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -lt 2 || "$#" -gt 5 ]]; then
  echo "Usage: $0 EXPECTED_COMMIT OUTPUT_DIRECTORY [WINDOWS_NODE] [LINUX_NODE] [PROVER_DIRECTORY]" >&2
  exit 2
fi

expected_commit="$1"
output_directory="$(realpath -m "$2")"
project_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
windows_node="${3:-$project_root/target/release/cmfd-node.exe}"
linux_node="${4:-$project_root/target-linux/release/cmfd-node}"
prover_directory="${5:-$project_root/tools/production-v4-prover/target/release}"
dashboard="$project_root/apps/pool-dashboard/dist"
shared="$project_root/packaging/production-v4-pool/shared"
release_integrity="$project_root/scripts/release_integrity.py"

current_commit="$(git -C "$project_root" rev-parse HEAD)"
if [[ "$current_commit" != "$expected_commit" ]]; then
  echo "ERROR: expected commit $expected_commit, found $current_commit" >&2
  exit 1
fi

for command_name in cargo cp find git mkdir mktemp python3 realpath sha256sum sort xargs; do
  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "ERROR: $command_name is required." >&2
    exit 1
  fi
done
for file in \
  "$windows_node" \
  "$linux_node" \
  "$prover_directory/cmfd-v4-replay" \
  "$prover_directory/real_bank0_relations" \
  "$dashboard/index.html" \
  "$shared/V4-INPUT-CHUNKS.json" \
  "$shared/production-v4-testnet-1-inputs.json" \
  "$shared/FORGEMATRIX-V4-FIXED-ARTIFACT-RECORD-V1.json"; do
  if [[ ! -f "$file" ]]; then
    echo "ERROR: required package input is missing: $file" >&2
    exit 1
  fi
done

version="$(cargo metadata --manifest-path "$project_root/Cargo.toml" --no-deps --format-version 1 --locked |
  python3 -c 'import json,sys; data=json.load(sys.stdin); print(next(p["version"] for p in data["packages"] if p["name"] == "cmfd-node"))')"
source_date_epoch="${SOURCE_DATE_EPOCH:-$(git -C "$project_root" show -s --format=%ct "$expected_commit")}"
windows_name="commonfoundry-pool-v${version}-windows-x86_64-wsl2"
linux_name="commonfoundry-pool-v${version}-linux-x86_64"
windows_archive="$output_directory/$windows_name.zip"
linux_archive="$output_directory/$linux_name.tar.gz"

if [[ -e "$windows_archive" || -e "$linux_archive" ]]; then
  echo "ERROR: a pool package already exists in $output_directory" >&2
  exit 1
fi

work="$(mktemp -d)"
trap 'rm -rf -- "$work"' EXIT
mkdir -p -- "$output_directory"

copy_common() {
  local stage="$1"
  mkdir -p -- "$stage/dashboard"
  cp -R -- "$dashboard/." "$stage/dashboard/"
  cp -- "$project_root/scripts/production-v4-inputs.py" "$stage/production-v4-inputs.py"
  cp -- "$shared/V4-INPUT-CHUNKS.json" "$stage/V4-INPUT-CHUNKS.json"
  cp -- "$shared/production-v4-testnet-1-inputs.json" "$stage/production-v4-testnet-1-inputs.json"
  cp -- "$shared/FORGEMATRIX-V4-FIXED-ARTIFACT-RECORD-V1.json" "$stage/FORGEMATRIX-V4-FIXED-ARTIFACT-RECORD-V1.json"
  cp -- "$project_root/docs/production-v4-pool.md" "$stage/README.md"
  cp -- "$project_root/LICENSE" "$stage/LICENSE"
  cp -- "$project_root/THIRD_PARTY_NOTICES.md" "$stage/THIRD_PARTY_NOTICES.md"
  cp -- "$project_root/docs/release-notes/v0.1.0-devnet.16.md" "$stage/RELEASE_NOTES.md"
  cp -- "$prover_directory/cmfd-v4-replay" "$stage/cmfd-v4-replay"
  cp -- "$prover_directory/real_bank0_relations" "$stage/real_bank0_relations"
}

write_package_hashes() {
  local stage="$1"
  (
    cd -- "$stage"
    find . -type f ! -name PACKAGE-SHA256SUMS.txt -print0 |
      sort -z |
      xargs -0 sha256sum
  ) > "$stage/PACKAGE-SHA256SUMS.txt"
}

windows_stage="$work/$windows_name"
mkdir -- "$windows_stage"
copy_common "$windows_stage"
cp -- "$windows_node" "$windows_stage/cmfd-node.exe"
cp -- "$project_root/packaging/production-v4-pool/windows/START-POOL.bat" "$windows_stage/START-POOL.bat"
cp -- "$project_root/scripts/run-production-v4-pool.ps1" "$windows_stage/START-POOL.ps1"
cp -- "$project_root/scripts/control-production-v4-pool.ps1" "$windows_stage/POOL-CONTROL.ps1"
for control in POOL-CONTROL POOL-STATUS STOP-POOL RESTART-POOL INSTALL-POOL-AUTOSTART REMOVE-POOL-AUTOSTART; do
  cp -- "$project_root/packaging/production-v4-pool/windows/$control.bat" "$windows_stage/$control.bat"
done
cp -- "$project_root/packaging/production-v4-testnet/windows/PREPARE-V4-INPUTS.ps1" "$windows_stage/PREPARE-V4-INPUTS.ps1"
write_package_hashes "$windows_stage"

linux_stage="$work/$linux_name"
mkdir -- "$linux_stage"
copy_common "$linux_stage"
cp -- "$linux_node" "$linux_stage/cmfd-node"
cp -- "$project_root/scripts/run-production-v4-pool.sh" "$linux_stage/START-POOL.sh"
cp -- "$project_root/scripts/control-production-v4-pool.py" "$linux_stage/POOL-CONTROL.py"
for control in POOL-STATUS STOP-POOL RESTART-POOL INSTALL-POOL-SERVICE REMOVE-POOL-SERVICE; do
  cp -- "$project_root/packaging/production-v4-pool/linux/$control.sh" "$linux_stage/$control.sh"
done
cp -- "$project_root/packaging/production-v4-testnet/linux/PREPARE-V4-INPUTS.sh" "$linux_stage/PREPARE-V4-INPUTS.sh"
chmod 755 \
  "$linux_stage/cmfd-node" \
  "$linux_stage/cmfd-v4-replay" \
  "$linux_stage/real_bank0_relations" \
  "$linux_stage/POOL-CONTROL.py" \
  "$linux_stage/POOL-STATUS.sh" \
  "$linux_stage/STOP-POOL.sh" \
  "$linux_stage/RESTART-POOL.sh" \
  "$linux_stage/INSTALL-POOL-SERVICE.sh" \
  "$linux_stage/REMOVE-POOL-SERVICE.sh" \
  "$linux_stage/START-POOL.sh" \
  "$linux_stage/PREPARE-V4-INPUTS.sh"
write_package_hashes "$linux_stage"

python3 "$release_integrity" archive-zip \
  --stage "$windows_stage" \
  --output "$windows_archive" \
  --source-date-epoch "$source_date_epoch"
python3 "$release_integrity" archive-tar-gz \
  --stage "$linux_stage" \
  --output "$linux_archive" \
  --source-date-epoch "$source_date_epoch"

sha256sum -- "$windows_archive" "$linux_archive"
