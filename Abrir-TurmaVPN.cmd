@echo off
setlocal
cd /d "%~dp0"
py -3 cliente.py
if errorlevel 1 pause
