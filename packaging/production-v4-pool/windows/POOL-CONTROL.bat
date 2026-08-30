@echo off
setlocal
set "POWERSHELL_EXE=powershell.exe"
where pwsh.exe >nul 2>&1
if not errorlevel 1 set "POWERSHELL_EXE=pwsh.exe"
if not exist "%~dp0POOL-CONTROL.ps1" (
  echo ERROR: POOL-CONTROL.ps1 is missing from this package.
  exit /b 1
)
if "%~1"=="" (
  echo Usage: %~nx0 Status^|Stop^|Restart^|InstallAutostart^|RemoveAutostart [options]
  exit /b 2
)
set "POOL_ACTION=%~1"
shift
"%POWERSHELL_EXE%" -NoProfile -ExecutionPolicy Bypass -File "%~dp0POOL-CONTROL.ps1" -Action "%POOL_ACTION%" %1 %2 %3 %4 %5 %6 %7 %8 %9
exit /b %ERRORLEVEL%
