@echo off
setlocal
title Common Foundry Mainnet Miner
rem Optional: fill these in, or leave blank for the interactive prompts.
set "WALLET_ADDRESS="
set "POOL_URL="
set "WORKER_NAME=%COMPUTERNAME%"
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0START-MINER.ps1" -WalletAddress "%WALLET_ADDRESS%" -PoolUrl "%POOL_URL%" -WorkerName "%WORKER_NAME%"
set "result=%ERRORLEVEL%"
if not "%result%"=="0" pause
exit /b %result%
