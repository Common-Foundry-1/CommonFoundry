#!/usr/bin/env bash
set -euo pipefail
repo="$(cd "$(dirname "$0")/.." && pwd)"
out="$repo/target/compact-public"
old=/mnt/c/Source/_research/cmfd-16gb-proof-budget-20261103
research=/mnt/c/Source/_research/cmfd-direct-testnet-20261105
mkdir -p "$out/artifacts"
if [ ! -d "$out/gpu-prover" ]; then
  cp -R "$research/gpu-prover" "$out/gpu-prover"
  cp "$research/batch_reduction.cu" "$out/batch_reduction.cu"
  python3 - "$out/gpu-prover/Cargo.toml" <<'PY'
from pathlib import Path
import sys
p=Path(sys.argv[1]);s=p.read_text()
s=s.replace('../../cmfd-direct-batched-proof-20261105','/mnt/c/Source/_research/cmfd-direct-batched-proof-20261105')
s=s.replace('../../cmfd-control-proving-profile-20261103/reference-mainnet','/mnt/c/Source/_research/cmfd-control-proving-profile-20261103/reference-mainnet')
p.write_text(s)
PY
fi
export PATH="$old/build-bin:/root/.cargo/bin:/root/cmfd-cuda-12.9.1-repro/toolkit/bin:/usr/bin:/bin"
export CARGO_BUILD_JOBS=4 CMAKE_BUILD_PARALLEL_LEVEL=4 CARGO_INCREMENTAL=0 GOMAXPROCS=4 RAYON_NUM_THREADS=4
export CMAKE="$old/build-bin/cmake" CUDA_PATH=/root/cmfd-cuda-12.9.1-repro/toolkit CUDA_HOME=/root/cmfd-cuda-12.9.1-repro/toolkit
export SP1_CUDA_ENABLED=1 CUDA_ARCHS='86;89;120' CUDACXX=/root/cmfd-cuda-12.9.1-repro/toolkit/bin/nvcc
export CUDAToolkit_ROOT=/root/cmfd-cuda-12.9.1-repro/toolkit CMAKE_TOOLCHAIN_FILE="$old/cuda-toolchain.cmake"
export CARGO_TARGET_DIR=/mnt/c/Source/_releases/cmfd-v1019/final/proof-frozen/producer-target-cache
export RUSTFLAGS="--remap-path-prefix=$repo=/commonfoundry-direct-testnet --remap-path-prefix=/mnt/c/Source/_releases/cmfd-v1019/final/proof-frozen/target=/cmfd-gpu-build"
cd "$repo"
cargo +1.97.1 test --offline --locked -p cmfd-consensus --features direct-proof-testnet --lib > "$out/consensus-tests.log" 2>&1
cargo +1.97.1 test --offline --locked -p cmfd-node --features direct-proof-testnet network_profile::tests --lib > "$out/profile-tests.log" 2>&1
cargo +1.97.1 build --release --offline --locked -p cmfd-node -p cmfd-miner --features cmfd-node/direct-proof-testnet,cmfd-miner/direct-proof-testnet > "$out/node-build.log" 2>&1
cp "$CARGO_TARGET_DIR/release/cmfd-node" "$out/artifacts/cmfd-node"
cp "$CARGO_TARGET_DIR/release/cmfd-miner" "$out/artifacts/cmfd-miner"
cd "$out/gpu-prover"
cargo +1.97.1 test --release --locked --offline --bin cmfd-all-relations-first-foundation > "$out/prover-tests.log" 2>&1
cargo +1.97.1 build --release --locked --offline --bin cmfd-all-relations-first-foundation > "$out/prover-build.log" 2>&1
cp "$CARGO_TARGET_DIR/release/cmfd-all-relations-first-foundation" "$out/artifacts/cmfd-direct-prover"
cp /root/cmfd-proof-5090/worker/cmfd-v4-replay "$out/artifacts/cmfd-v4-replay"
"$out/artifacts/cmfd-direct-prover" network-info > "$out/worker-network-info.json"
sha256sum "$out/artifacts/"* > "$out/artifact-hashes.txt"
echo 'Public testnet build complete'
