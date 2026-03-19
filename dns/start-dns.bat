@echo off
title LinkShield DNS
echo.
echo  Starting LinkShield DNS Protection...
echo.
cd /d "%~dp0"
node shield-dns.mjs
pause
