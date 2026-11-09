@echo off
setlocal
set "SALTSCORE_SAVED_VCPKG_ROOT=%VCPKG_ROOT%"
call "%VSDEVCMD_BAT%" -arch=x64 -host_arch=x64 >nul
if errorlevel 1 exit /b %errorlevel%
set "VCPKG_ROOT=%SALTSCORE_SAVED_VCPKG_ROOT%"
%*
exit /b %errorlevel%
