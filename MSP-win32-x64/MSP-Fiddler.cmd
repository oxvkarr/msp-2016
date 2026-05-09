@echo off
setlocal
set MSP_DEBUG=1
set MSP_FIDDLER=1
set MSP_FIDDLER_PROXY=127.0.0.1:8888
set MSP_FIDDLER_BASE_URL=http://127.0.0.1
start "" "%~dp0MSP-Debug.exe" --debug --fiddler
