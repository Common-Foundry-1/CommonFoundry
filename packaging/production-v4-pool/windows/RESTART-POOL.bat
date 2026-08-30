@echo off
setlocal
call "%~dp0POOL-CONTROL.bat" Restart %*
exit /b %ERRORLEVEL%
