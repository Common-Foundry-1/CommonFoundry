#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
echo 'Close the wallet first. Solo mining needs approximately 61 GB of model inputs and an NVIDIA GPU.'
command -v nvidia-smi >/dev/null || { echo 'ERROR: NVIDIA drivers are required for mining.' >&2; exit 1; }
for worker in cmfd-v4-replay real_bank0_relations; do
  [[ -x "$SCRIPT_DIR/production-v4/$worker" ]] || { echo "ERROR: packaged worker $worker is missing." >&2; exit 1; }
done
"$SCRIPT_DIR/prepare-runtime.sh" "$SCRIPT_DIR/production-v4" miner
echo 'Solo-mining inputs are ready. Start the wallet; mining remains gated by activation.'
