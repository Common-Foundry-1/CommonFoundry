@echo off
setlocal
title Common Foundry ProductionV3 Testnet Wallet

if not exist "%~dp0common-foundry-wallet.exe" (
  echo ERROR: common-foundry-wallet.exe is missing from this folder.
  pause
  exit /b 1
)

start "" "%~dp0common-foundry-wallet.exe"
