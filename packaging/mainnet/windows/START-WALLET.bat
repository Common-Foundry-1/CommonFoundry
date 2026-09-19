@echo off
setlocal
title Common Foundry Mainnet Wallet
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0START-RUNTIME.ps1" -Mode Wallet
set "result=%ERRORLEVEL%"
if not "%result%"=="0" pause
exit /b %result%
