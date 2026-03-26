@echo off
setlocal
set "PS_EXE=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if not exist "%PS_EXE%" set "PS_EXE=powershell"
"%PS_EXE%" -ExecutionPolicy Bypass -File "%~dp0codesentinel.ps1" %*
exit /b %errorlevel%
