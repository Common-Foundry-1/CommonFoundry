@echo off
setlocal
title Common Foundry Wallet RCNet-1
set "ROOT=%~dp0"
cd /d "%ROOT%"
set "POWERSHELL_EXE=powershell.exe"
where pwsh.exe >nul 2>&1
if not errorlevel 1 set "POWERSHELL_EXE=pwsh.exe"
if not exist "%ROOT%common-foundry-wallet.exe" (
  echo ERROR: common-foundry-wallet.exe is missing from this package.
  exit /b 1
)
"%POWERSHELL_EXE%" -NoProfile -ExecutionPolicy Bypass -File "%ROOT%PREPARE-RCNET-RUNTIME.ps1" -Destination "%ROOT%production-v4"
if errorlevel 1 (
  echo ERROR: RCNet-1 runtime preparation failed. Keep this window open to inspect the error.
  exit /b 1
)
start "Common Foundry Wallet RCNet-1" "%ROOT%common-foundry-wallet.exe"
