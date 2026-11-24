@echo off
setlocal
for %%I in ("%~dp0..") do set "PROJECT_ROOT=%%~fI"
cd /d "%PROJECT_ROOT%"
set CHECKPOINT_DEV_MODE=1
if exist "%PROJECT_ROOT%\venv\Scripts\python.exe" (
    "%PROJECT_ROOT%\venv\Scripts\python.exe" -m core.antigravity_adapter
) else (
    python -m core.antigravity_adapter
)
exit /b %ERRORLEVEL%
