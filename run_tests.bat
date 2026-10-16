@echo off
setlocal
echo ========================================================
echo  Mission 4: Automated Testing and Security Verification Suite
echo ========================================================
echo.

if exist "C:\Users\sures\python311\python.exe" (
    "C:\Users\sures\python311\python.exe" -m pytest -v
) else (
    python -m pytest -v
)

echo.
echo ========================================================
echo  Automated Test Execution Complete!
echo ========================================================
pause
