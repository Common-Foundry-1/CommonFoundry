@echo off
setlocal
title Common Foundry ProductionV4 Testnet Wallet
set "WALLET_RUNTIME=%~dp0runtime"

set "POWERSHELL_EXE=powershell.exe"
where pwsh.exe >nul 2>&1
if not errorlevel 1 set "POWERSHELL_EXE=pwsh.exe"
if not exist "%WALLET_RUNTIME%\common-foundry-wallet.exe" (
  echo ERROR: runtime\common-foundry-wallet.exe is missing from this package.
  pause
  exit /b 1
)

"%POWERSHELL_EXE%" -NoProfile -ExecutionPolicy Bypass -File "%~dp0PREPARE-V4-NODE-INPUTS.ps1" -Destination "%WALLET_RUNTIME%\production-v4"
if errorlevel 1 (
  echo ERROR: ProductionV4 verifier inputs could not be prepared.
  pause
  exit /b 1
)

start "" "%WALLET_RUNTIME%\common-foundry-wallet.exe" --peer 107.214.187.2:22444 --allow-public-peers --p2p-bind 127.0.0.1:22445
