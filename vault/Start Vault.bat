@echo off
setlocal
cd /d "%~dp0"
set "NODE=C:\Users\HP\.cache\codex-runtimes\codex-primary-runtime\dependencies\node\bin\node.exe"
if not exist "%NODE%" (
  echo Vault could not find its bundled Node.js runtime.
  echo Please open this folder in Codex and ask to start the Vault server.
  pause
  exit /b 1
)
start "Vault API" /min "%NODE%" server.mjs
ping 127.0.0.1 -n 3 >nul
start "" "http://localhost:4173/"
