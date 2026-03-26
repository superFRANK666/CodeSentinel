@echo off
setlocal
chcp 65001 >nul

echo CodeSentinel AI Security Audit Tool v2.0.0
echo =============================================
echo.

set "PS_EXE=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if not exist "%PS_EXE%" set "PS_EXE=powershell"

REM Pass through command-line arguments for non-interactive usage
if not "%~1"=="" (
    echo Arguments detected, executing directly:
    echo   %PS_EXE% -ExecutionPolicy Bypass -File codesentinel.ps1 %*
    echo.
    "%PS_EXE%" -ExecutionPolicy Bypass -File .\codesentinel.ps1 %*
    exit /b %errorlevel%
)

REM Create .env on first run and verify result
if not exist ".env" (
    echo First run: Creating configuration file .env ...
    copy ".env.example" ".env" >nul 2>&1
    if errorlevel 1 (
        echo [ERROR] Failed to create .env automatically. Check directory write permissions.
        echo [TIP] You can manually run: copy .env.example .env
        echo.
    ) else (
        if exist ".env" (
            echo [OK] Configuration file created: .env
            echo [TIP] To use AI analysis, add your OPENAI_API_KEY to .env
            echo.
        ) else (
            echo [ERROR] .env not detected. Please manually copy .env.example
            echo.
        )
    )
)

echo Usage Guide
echo =============================================
echo.
echo Common commands:
echo   %PS_EXE% -ExecutionPolicy Bypass -File .\codesentinel.ps1 spec-version
echo   %PS_EXE% -ExecutionPolicy Bypass -File .\codesentinel.ps1 doctor -Format json
echo   %PS_EXE% -ExecutionPolicy Bypass -File .\codesentinel.ps1 scan . -AnalyzerMode local-only -Format json -Output report.json
echo   %PS_EXE% -ExecutionPolicy Bypass -File .\codesentinel.ps1 scan . -Format sarif -Output report.sarif
echo   %PS_EXE% -ExecutionPolicy Bypass -File .\codesentinel.ps1 config-validate
echo.
echo Quick actions:
echo   [1] Show spec version
echo   [2] Run environment diagnostics
echo   [3] Local scan of current directory (JSON output)
echo   [4] Exit
echo   [Enter] Launch native interactive menu
echo.

set /p choice="Select [1/2/3/4/Enter]: "

if "%choice%"=="1" (
    echo.
    "%PS_EXE%" -ExecutionPolicy Bypass -File .\codesentinel.ps1 spec-version
) else if "%choice%"=="2" (
    echo.
    "%PS_EXE%" -ExecutionPolicy Bypass -File .\codesentinel.ps1 doctor -Format json
) else if "%choice%"=="3" (
    echo.
    "%PS_EXE%" -ExecutionPolicy Bypass -File .\codesentinel.ps1 scan . -AnalyzerMode local-only -Format json -Output report.json
) else if "%choice%"=="4" (
    goto :end
) else (
    echo.
    echo Launching native interactive menu...
    .\CodeSentinel.exe
)

:end
echo.
pause
endlocal
