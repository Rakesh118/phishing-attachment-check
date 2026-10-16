@echo off
setlocal
echo ========================================================
echo  Launching Phishing Risk Checker SOC Dashboard (Streamlit)
echo ========================================================
echo.

if exist "C:\Users\sures\python311\python.exe" (
    "C:\Users\sures\python311\python.exe" -m streamlit run app.py
) else (
    python -m streamlit run app.py
)
pause
