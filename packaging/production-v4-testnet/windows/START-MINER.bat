@echo off
setlocal
title Common Foundry ProductionV4 Testnet Miner

set "POWERSHELL_EXE=powershell.exe"
where pwsh.exe >nul 2>&1
if not errorlevel 1 set "POWERSHELL_EXE=pwsh.exe"
if not exist "%~dp0START-MINER.ps1" (
  echo ERROR: START-MINER.ps1 is missing from this package.
  pause
  exit /b 1
)

if "%~1"=="" (
  "%POWERSHELL_EXE%" -NoProfile -ExecutionPolicy Bypass -File "%~dp0START-MINER.ps1"
) else (
  "%POWERSHELL_EXE%" -NoProfile -ExecutionPolicy Bypass -File "%~dp0START-MINER.ps1" -Miner "%~1"
)
set "MINER_EXIT=%ERRORLEVEL%"
if not "%MINER_EXIT%"=="0" echo ERROR: Miner stopped with exit code %MINER_EXIT%.
pause
exit /b %MINER_EXIT%
