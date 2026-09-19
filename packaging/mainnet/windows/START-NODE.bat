@echo off
setlocal
title Common Foundry Mainnet Node
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0START-RUNTIME.ps1" -Mode Node
set "result=%ERRORLEVEL%"
if not "%result%"=="0" pause
exit /b %result%
