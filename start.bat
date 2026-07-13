@echo off
echo ========================================================
echo PhantomShield AI - Startup Script
echo ========================================================

:: Step 1: Check for Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python is not installed or not in PATH. Please install Python 3.9+.
    pause
    exit /b
)

:: Step 2: Create/Activate Virtual Environment
if not exist .venv (
    echo [INFO] Creating virtual environment...
    python -m venv .venv
)

echo [INFO] Activating virtual environment...
call .venv\Scripts\activate.bat

:: Step 3: Install dependencies
echo [INFO] Installing backend dependencies...
pip install -r backend\requirements.txt -q

echo [INFO] Installing frontend dependencies...
pip install -r frontend\requirements.txt -q

:: Step 4: Ensure .env exists in backend
if not exist backend\.env (
    echo [INFO] Creating default backend\.env file from template...
    copy .env.example backend\.env >nul
    echo [WARN] Edit backend\.env and add your GROQ_API_KEY for the AI assistant.
)

:: Step 5: Check ML model
if not exist backend\ai_engines\url_phishing_model.pkl (
    echo [WARN] ML model not found. URL scanner will use enhanced heuristics.
    echo [INFO] To train the AI model, run:
    echo        cd backend\ai_engines ^&^& ..\..\.venv\Scripts\python.exe train_url_model.py
    echo.
)

:: Step 6: Start the backend server in a new window
echo [INFO] Starting Flask backend server on http://localhost:5000 ...
start "PhantomShield Backend" cmd /k "cd backend && ..\.venv\Scripts\python.exe app.py"

:: Wait for backend to initialize
timeout /t 3 /nobreak >nul

:: Step 7: Start the frontend Streamlit server
echo [INFO] Starting Streamlit frontend on http://localhost:8501 ...
cd frontend
..\.venv\Scripts\streamlit.exe run app.py

pause
