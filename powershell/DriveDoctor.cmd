@echo off
rem Launches DriveDoctor (it asks for administrator rights itself).
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0DriveDoctor.ps1"
