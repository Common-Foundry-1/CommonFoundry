@echo off
setlocal
title Common Foundry ProductionV3 Testnet Node

if not exist "%~dp0cmfd-node.exe" (
  echo ERROR: cmfd-node.exe is missing from this folder.
  pause
  exit /b 1
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
