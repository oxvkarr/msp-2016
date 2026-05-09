@echo off
setlocal
set MSP_DEBUG=1
set MSP_FIDDLER=0
start "" "%~dp0MSP-Debug.exe" --debug
