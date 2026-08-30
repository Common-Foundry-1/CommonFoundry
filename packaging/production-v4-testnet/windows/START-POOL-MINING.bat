@echo off
setlocal EnableExtensions
title Common Foundry ProductionV4 Pool Miner

rem ================================================================
rem EDIT ONLY THESE THREE VALUES
set "WALLET_ADDRESS="
set "POOL_URL="
set "WORKER_NAME=%COMPUTERNAME%"
rem ================================================================

set "POWERSHELL_EXE=powershell.exe"
where pwsh.exe >nul 2>&1
if not errorlevel 1 set "POWERSHELL_EXE=pwsh.exe"
if not exist "%~dp0START-POOL-MINING.ps1" (
  echo ERROR: START-POOL-MINING.ps1 is missing from this miner package.
  pause
  exit /b 1
)

"%POWERSHELL_EXE%" -NoProfile -ExecutionPolicy Bypass -File "%~dp0START-POOL-MINING.ps1" -WalletAddress "%WALLET_ADDRESS%" -PoolUrl "%POOL_URL%" -WorkerName "%WORKER_NAME%"
set "MINER_EXIT=%ERRORLEVEL%"
if not "%MINER_EXIT%"=="0" echo ERROR: Pool miner stopped with exit code %MINER_EXIT%.
pause
exit /b %MINER_EXIT%
