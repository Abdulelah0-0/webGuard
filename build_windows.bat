@echo off
setlocal
cd /d "%~dp0"
where python >nul 2>nul
if errorlevel 1 (
    echo Python 3.10 or newer is required on PATH.
    exit /b 1
)
python -c "import sys; sys.exit(not ((3, 10) <= sys.version_info[:2] <= (3, 13)))"
if errorlevel 1 (
    echo This build supports Python 3.10 through 3.13.
    exit /b 1
)
if not exist ".build-env\Scripts\python.exe" (
    python -m venv --without-pip ".build-env"
    if errorlevel 1 exit /b 1
)
if not exist ".build-env\tmp" mkdir ".build-env\tmp"
set "TEMP=%CD%\.build-env\tmp"
set "TMP=%TEMP%"
python -m pip --python ".build-env\Scripts\python.exe" install --disable-pip-version-check -r requirements-build.txt -r requirements-report.txt
if errorlevel 1 exit /b 1
".build-env\Scripts\python.exe" -m PyInstaller --noconfirm --clean --onefile --windowed --name WebGuard --icon webguard.ico --add-data "webguard.ico:." webguard_desktop.py
if errorlevel 1 exit /b 1
echo Created dist\WebGuard.exe



