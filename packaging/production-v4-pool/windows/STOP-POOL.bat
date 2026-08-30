@echo off
setlocal
call "%~dp0POOL-CONTROL.bat" Stop %*
set "POOL_EXIT=%ERRORLEVEL%"
pause
exit /b %POOL_EXIT%
