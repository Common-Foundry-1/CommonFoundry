@echo off
setlocal
title Common Foundry ProductionV3 Testnet Wallet

if not exist "%~dp0common-foundry-wallet.exe" (
  echo ERROR: common-foundry-wallet.exe is missing from this folder.
  pause
  exit /b 1
)

rem ProductionV3 refuses to load its Record V2 from a directory other accounts
rem can reach. Extracting a ZIP leaves the folder's inherited permissions in
rem place, so tighten them here. SYSTEM and Administrators are named by
rem well-known SID so this also works on non-English Windows.
if exist "%~dp0production-v3" (
  icacls "%~dp0production-v3" /inheritance:r /grant:r "%USERNAME%:(OI)(CI)F" "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" >nul 2>&1
  if errorlevel 1 echo WARNING: could not make production-v3 private; the wallet may refuse to start.
)

rem The wallet's embedded node keeps its default local P2P bind; inbound
rem service belongs to the node package. A wildcard --p2p-bind is refused.
start "" "%~dp0common-foundry-wallet.exe" ^
  --peer 107.214.187.2:21444 ^
  --allow-public-peers
