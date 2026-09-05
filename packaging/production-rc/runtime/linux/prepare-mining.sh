#!/usr/bin/env bash
set -euo pipefail
umask 077
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
DESTINATION="$SCRIPT_DIR/production-v4"
for tool in curl python3 sha256sum nvidia-smi; do
  command -v "$tool" >/dev/null || { echo "ERROR: $tool is required." >&2; exit 1; }
done
echo 'Close the wallet first. This explicitly downloads about 61 GB of inputs plus 37 MB of GPU workers.'
mkdir -p "$DESTINATION"
python3 - "$SCRIPT_DIR/MINING-WORKERS.json" "$DESTINATION" <<'PY'
import hashlib, json, os, pathlib, subprocess, sys
manifest = json.loads(pathlib.Path(sys.argv[1]).read_bytes())
if manifest['schema_version'] != 1 or not manifest['release_base'].startswith('https://github.com/JustAResearcher/CommonFoundry-Binaries/releases/download/v'):
    raise SystemExit('Invalid mining worker manifest')
for worker in manifest['workers']:
    name = worker['name']
    if name not in {'cmfd-v4-replay', 'real_bank0_relations'}:
        raise SystemExit('Unknown mining worker')
    output = pathlib.Path(sys.argv[2]) / name
    def valid(path):
        return path.is_file() and path.stat().st_size == worker['bytes'] and hashlib.sha256(path.read_bytes()).hexdigest() == worker['sha256']
    if not valid(output):
        download = output.with_name(name + '.download')
        subprocess.run(['curl', '--fail', '--location', '--retry', '3', '--connect-timeout', '30', '--output', str(download), manifest['release_base'] + '/' + name], check=True)
        if not valid(download):
            raise SystemExit('Mining worker download failed authentication: ' + name)
        os.replace(download, output)
    output.chmod(0o755)
PY
python3 "$SCRIPT_DIR/production-v4-inputs.py" \
  --chunk-manifest "$SCRIPT_DIR/V4-INPUT-CHUNKS.json" \
  --input-manifest "$SCRIPT_DIR/production-v4-rcnet-1-inputs.json" \
  --fixed-record "$SCRIPT_DIR/FORGEMATRIX-V4-FIXED-ARTIFACT-RECORD-V1.json" \
  --destination "$DESTINATION" --role miner \
  --release-base https://downloads.commonfoundry.ai/v0.1.0-rc.1 \
  --fallback-release-base https://github.com/JustAResearcher/CommonFoundry-Binaries/releases/download/v0.1.0-rc.1
cp "$DESTINATION/fixed/FORGEMATRIX-V4-FIXED-ARTIFACT-RECORD-V1.json" "$DESTINATION/"
echo 'Mining inputs are ready. Reopen start-wallet.sh, unlock your wallet, then choose Mining and Start Solo Mining.'
