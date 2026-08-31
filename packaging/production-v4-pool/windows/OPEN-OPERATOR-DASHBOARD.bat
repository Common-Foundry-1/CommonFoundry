@echo off
setlocal
title Common Foundry Pool Operator Console

if not exist "%~dp0POOL-OPERATOR.py" (
  echo ERROR: POOL-OPERATOR.py is missing from this package.
  pause
  exit /b 1
)

where py.exe >nul 2>&1
if not errorlevel 1 (
  py.exe -3 "%~dp0POOL-OPERATOR.py" --bundle-dir "%~dp0" --open-browser %*
  set "OPERATOR_EXIT=%ERRORLEVEL%"
) else (
  where python.exe >nul 2>&1
  if errorlevel 1 (
    echo ERROR: Python 3 is required to run the local operator dashboard.
    echo Install Python 3, then run OPEN-OPERATOR-DASHBOARD.bat again.
    pause
    exit /b 1
  )
  python.exe "%~dp0POOL-OPERATOR.py" --bundle-dir "%~dp0" --open-browser %*
  set "OPERATOR_EXIT=%ERRORLEVEL%"
)

if not "%OPERATOR_EXIT%"=="0" (
  echo ERROR: Operator dashboard stopped with exit code %OPERATOR_EXIT%.
  pause
)
exit /b %OPERATOR_EXIT%
