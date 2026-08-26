@echo off
setlocal
title Common Foundry ProductionV3 Testnet Node

if not exist "%~dp0cmfd-node.exe" (
  echo ERROR: cmfd-node.exe is missing from this folder.
  pause
  exit /b 1
)

rem ProductionV3 refuses to load its Record V2 from a directory other accounts
rem can reach. Extracting a ZIP leaves the folder's inherited permissions in
rem place, so tighten them here. SYSTEM and Administrators are named by
rem well-known SID so this also works on non-English Windows.
if exist "%~dp0production-v3" (
  icacls "%~dp0production-v3" /inheritance:r /grant:r "%USERNAME%:(OI)(CI)F" "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" >nul 2>&1
  if errorlevel 1 echo WARNING: could not make production-v3 private; the node may refuse to start.
)

echo Starting ProductionV3 Testnet-1 node...
echo P2P: 0.0.0.0:21444  RPC: 127.0.0.1:21443
"%~dp0cmfd-node.exe" --data-dir "%~dp0data" -vv run ^
  --bind 127.0.0.1:21443 ^
  --p2p-bind 0.0.0.0:21444 ^
  --peer 107.214.187.2:21444 ^
  --allow-public-peers

echo.
echo Node stopped with exit code %ERRORLEVEL%.
pause
