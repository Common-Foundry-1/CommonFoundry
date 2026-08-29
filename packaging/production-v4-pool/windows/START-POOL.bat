@echo off
setlocal
title Common Foundry ProductionV4 Testnet Pool

set "POWERSHELL_EXE=powershell.exe"
where pwsh.exe >nul 2>&1
if not errorlevel 1 set "POWERSHELL_EXE=pwsh.exe"
if not exist "%~dp0START-POOL.ps1" (
  echo ERROR: START-POOL.ps1 is missing from this package.
  pause
  exit /b 1
)

"%POWERSHELL_EXE%" -NoProfile -ExecutionPolicy Bypass -File "%~dp0START-POOL.ps1" %*
set "POOL_EXIT=%ERRORLEVEL%"
if not "%POOL_EXIT%"=="0" echo ERROR: Pool stopped with exit code %POOL_EXIT%.
pause
exit /b %POOL_EXIT%
