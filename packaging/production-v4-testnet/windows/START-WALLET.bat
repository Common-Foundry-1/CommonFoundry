@echo off
setlocal
title Common Foundry ProductionV4 Testnet Wallet

where pwsh.exe >nul 2>&1
if errorlevel 1 (
  echo ERROR: PowerShell 7 is required. Install it, then run START-WALLET.bat again.
  pause
  exit /b 1
)
if not exist "%~dp0common-foundry-wallet.exe" (
  echo ERROR: common-foundry-wallet.exe is missing from this folder.
  pause
  exit /b 1
)

pwsh.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0PREPARE-V4-NODE-INPUTS.ps1"
if errorlevel 1 (
  echo ERROR: ProductionV4 verifier inputs could not be prepared.
  pause
  exit /b 1
)

start "" "%~dp0common-foundry-wallet.exe" --peer 107.214.187.2:22444 --allow-public-peers
