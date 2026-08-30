@echo off
setlocal
call "%~dp0POOL-CONTROL.bat" RemoveAutostart %*
set "POOL_EXIT=%ERRORLEVEL%"
pause
exit /b %POOL_EXIT%
