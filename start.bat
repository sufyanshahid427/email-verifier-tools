@echo off
echo Starting Email Verifier...
echo.
echo 1. Starting Flask backend server...
start "Flask Server" cmd /k "python verify-app.py"
echo.
echo 2. Waiting 3 seconds for server to start...
timeout /t 3 /nobreak >nul
echo.
echo 3. Starting HTTP server for frontend...
start "HTTP Server" cmd /k "python -m http.server 5500"
echo.
echo 4. Opening browser...
timeout /t 2 /nobreak >nul
start http://localhost:5500
echo.
echo ✅ Email Verifier is now running!
echo 📧 Backend: http://localhost:5050
echo 🌐 Frontend: http://localhost:5500
echo.
echo Press any key to exit...
pause >nul
