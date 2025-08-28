@echo off
python --version >nul 2>&1
IF ERRORLEVEL 1 (
    echo Python is not installed. Please install Python to run the server.
    pause
    exit /b
)

echo Starting server at http://localhost
python -m http.server 80
pause
