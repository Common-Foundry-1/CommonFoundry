# Common Foundry Wallet - Compact Proof Testnet v0.5.2

This uses the existing Common Foundry desktop wallet and embedded CPU node. Double-click **START-WALLET.bat**. The first run downloads and checks the 6.44 GB model bank, then opens the usual wallet interface and connects to the public seed. Downloads resume if interrupted. `powershell.exe -NoProfile -File .\START-WALLET.ps1 -VerifyOnly` checks the package before starting it.

The wallet uses its own data directory under `%LOCALAPPDATA%\CommonFoundry\CompactTestnet1`. Mainnet keys and chain data are separate. The normal wallet window shows the selected network. Test coins have no monetary value.

This package needs Windows 10/11, the same WebView2 runtime as the existing wallet, and enough space for the model, temporary download parts, and chain data. Allow at least 30 GB free for initial setup and testing. The embedded node verifies compact proofs on the CPU without rerunning the mining calculation; it does not need CUDA or a GPU. Mining uses the separate compact testnet pool/miner kit.

Advanced users can run `runtime\cmfd-node.exe` with the packaged model and fixed record paths. The wallet's Network view can copy diagnostics for a sync report. Send us the version, height, peer count, and any error it reports.

To upgrade, close the older testnet wallet and extract v0.5.2 into a new kit
directory. Keep the default data directory to retain your testnet keys and
chain. Copy the older kit's `runtime\production-v4` directory into the new
kit's `runtime` directory to reuse downloaded inputs, then run VerifyOnly.
This continues the owner-approved unsigned Windows testnet preview.
