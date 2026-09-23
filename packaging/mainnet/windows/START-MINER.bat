@echo off
setlocal
title Common Foundry Mainnet Miner
rem Optional: fill these in, or leave blank for the interactive prompts.
set "WALLET_ADDRESS="
set "POOL_URL="
set "WORKER_NAME=%COMPUTERNAME%"
rem Optional: one physical GPU index (0, 1, ...) or full GPU-... UUID.
rem Start this BAT once per GPU with a distinct GPU value.
set "GPU=%CMFD_GPU%"
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0START-MINER.ps1" -WalletAddress "%WALLET_ADDRESS%" -PoolUrl "%POOL_URL%" -WorkerName "%WORKER_NAME%" -GpuSelector "%GPU%"
set "result=%ERRORLEVEL%"
if not "%result%"=="0" pause
exit /b %result%
