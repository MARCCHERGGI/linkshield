@echo off
title LinkShield Server
echo.
echo  Starting LinkShield Analysis Server...
echo.
cd /d "%~dp0server"
node server.mjs
pause
