@echo off
title LinkShield — Full Protection
echo.
echo  ================================================================
echo   LinkShield — Starting Full Protection Suite
echo  ================================================================
echo.

:: Kill any existing LinkShield processes on our ports
for /f "tokens=5" %%p in ('netstat -ano 2^>nul ^| findstr ":3847 " ^| findstr "LISTEN"') do (
    taskkill /F /PID %%p >nul 2>&1
)
for /f "tokens=5" %%p in ('netstat -ano 2^>nul ^| findstr ":3848 " ^| findstr "LISTEN"') do (
    taskkill /F /PID %%p >nul 2>&1
)
timeout /t 1 /nobreak >nul

echo  [1/2] Starting Analysis Server (port 3847)...
start /min "LinkShield-Server" cmd /c "cd /d C:\Users\hergi\Playground\link-shield\server && node server.mjs"
timeout /t 2 /nobreak >nul

echo  [2/2] Starting DNS Protection (port 53)...
start /min "LinkShield-DNS" cmd /c "cd /d C:\Users\hergi\Playground\link-shield\dns && node shield-dns.mjs"
timeout /t 2 /nobreak >nul

echo.
echo  ================================================================
echo   LinkShield ACTIVE
echo  ================================================================
echo.
echo   Analysis Server:  http://localhost:3847
echo   DNS Dashboard:    http://localhost:3848
echo   Phone DNS:        Set to your Tailscale IP
echo.
echo   Chrome Extension: chrome://extensions
echo     Load unpacked:  C:\Users\hergi\Playground\link-shield\extension
echo.
