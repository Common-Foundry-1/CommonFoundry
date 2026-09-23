@echo off
setlocal
rem Optional: set one physical GPU index or full GPU UUID per BAT copy.
set "GPU=%CMFD_GPU%"
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0START-MINER.ps1" -GpuSelector "%GPU%"
set "result=%ERRORLEVEL%"
if not "%result%"=="0" pause
exit /b %result%
