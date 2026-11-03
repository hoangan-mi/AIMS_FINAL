@echo off
setlocal
set "AIMS_DIR=%~dp0"
set "PYTHON_EXE=C:\Users\Admin\AppData\Local\Programs\Python\Python310\python.exe"

echo Starting AIMS...
start "AIMS Server" /D "%AIMS_DIR%" "%PYTHON_EXE%" "%AIMS_DIR%app.py"

ping 127.0.0.1 -n 4 >nul
echo.
echo Creating a phone-friendly link. Keep this window open.
echo Copy the https link shown below and open it on your phone.
"%AIMS_DIR%cloudflared.exe" tunnel --url http://127.0.0.1:5000
