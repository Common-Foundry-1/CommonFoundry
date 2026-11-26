# CPU pool credits

Stefan and AriaPool contributed the original CPU share verifier, CPU compact prover, AVX-512 VNNI replay kernel, and pool integration on which this update is based.

Common Foundry developed and tested the subsequent replay and proof optimizations, including weight reuse across activation rows, fixed-bank opening reductions, parallel commitments, and the 9950X3D replay/prover core scheduling profile.
