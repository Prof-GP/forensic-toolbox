@echo off
REM Forensic Toolbox - Windows Setup Script

echo ========================================
echo Forensic Toolbox - Windows Installation
echo ========================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python is not installed or not in PATH
    echo Please install Python 3.7+ from https://www.python.org/
    pause
    exit /b 1
)

echo [*] Python found!
python --version
echo.

REM Create virtual environment
echo [*] Creating virtual environment...
if exist venv (
    echo [!] Virtual environment already exists
    choice /C YN /M "Do you want to recreate it"
    if errorlevel 2 goto :skip_venv
    echo [*] Removing old virtual environment...
    rmdir /s /q venv
)

python -m venv venv
if %errorlevel% neq 0 (
    echo [ERROR] Failed to create virtual environment
    pause
    exit /b 1
)

:skip_venv
echo [+] Virtual environment ready!
echo.

REM Activate virtual environment and install
echo [*] Installing Forensic Toolbox...
call venv\Scripts\activate.bat

REM Upgrade pip
echo [*] Upgrading pip...
python -m pip install --upgrade pip setuptools wheel

REM Install package
echo [*] Installing package...
pip install -e .
if %errorlevel% neq 0 (
    echo [ERROR] Installation failed
    pause
    exit /b 1
)

echo.
echo ========================================
echo Installation Complete!
echo ========================================
echo.
echo To use Forensic Toolbox:
echo   1. Run: venv\Scripts\activate
echo   2. Run: forensic-toolbox ^<file^>
echo      or:  ftb ^<file^>
echo.
echo Example:
echo   forensic-toolbox SOFTWARE
echo   ftb evidence.lnk
echo.
echo To deactivate: deactivate
echo ========================================
echo.

REM Test installation
echo [*] Testing installation...
call forensic-toolbox --version
if %errorlevel% equ 0 (
    echo [+] Test successful!
) else (
    echo [!] Installation may have issues
)

echo.
pause