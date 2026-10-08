# Third-party notices

## GLib Rust bindings 0.18.5

The Linux wallet's GTK3 stack uses the MIT-licensed gtk-rs GLib bindings.
`third_party/glib-0.18.5-variant-str-iter` preserves the published crate's
LICENSE and COPYRIGHT and backports the upstream two-line fix for
RUSTSEC-2024-0429. Its source inventory and patch provenance are retained there.
Copyrights are retained by the gtk-rs contributors. This does not relicense
the separately installed GNOME libraries to which the bindings link.

## NVIDIA CUDA runtime library

Final mainnet packages require an unmodified, pinned Linux x86-64
`libcudart.so.12` for the ProductionV4 GPU workers. NVIDIA identifies Linux
`libcudart.so` as a distributable CUDA Toolkit component in Attachment A of
the [CUDA Toolkit EULA](https://docs.nvidia.com/cuda/eula/), subject to that
agreement's distribution requirements and limitations. The package's
`CUDA-RUNTIME-SHA256.txt` release evidence identifies the exact redistributed
object. Common Foundry does not grant an NVIDIA license or claim NVIDIA
endorsement; recipients must use the component consistently with the EULA.

## Offline ASERT arithmetic reference

The non-active difficulty comparison examples use the documented ASERT formula
and polynomial constants from Bitcoin Cash Node's `src/pow.cpp`.

Copyright (c) 2017-2020 The Bitcoin developers.
SPDX-License-Identifier: MIT. The MIT permission and disclaimer are reproduced
in this repository's `LICENSE`.

Reference: https://github.com/bitcoin-cash-node/bitcoin-cash-node/blob/master/src/pow.cpp

This comparison does not change the deployed matrix proof-of-work or select
ASERT as an active consensus rule.

## FreeForgeMiner replay kernels

The ProductionV4 replay worker's batched search includes changes from
FreeForgeMiner (https://github.com/pepsykolya/freeforgeminer, commit
`e696540d40c2ccbf5534def1dd8327b8d7430990`): the fused int8 GEMM and layer
reduce kernel in `tools/production-v4-prover/cuda/fused_limb_layer.cuh`, and in
`koala_four_limb_replay.cu` the persistent batch buffers, interleaved limb
rows, GPU final-activation digest and extra SM80 GEMM tile choices.

Copyright (c) 2026 FreeForgeMiner contributors.
SPDX-License-Identifier: MIT. The MIT permission and disclaimer are reproduced
in this repository's `LICENSE`.

## NVIDIA CUTLASS v3.9.2

The optional production CUDA tensor-core backend is compiled from CUTLASS
headers pinned to commit `ad7b2f5e84fcfa124cb02b91d5bd26d238c0459e`.

Copyright (c) 2017 - 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
SPDX-License-Identifier: BSD-3-Clause

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors
   may be used to endorse or promote products derived from this software without
   specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
