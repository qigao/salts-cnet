@echo off
setlocal
set "SALTSCORE_SAVED_VCPKG_ROOT=%VCPKG_ROOT%"
if not defined VSDEVCMD_ARCH set "VSDEVCMD_ARCH=%PROCESSOR_ARCHITECTURE%"
if /I "%VSDEVCMD_ARCH%"=="AMD64" set "VSDEVCMD_ARCH=x64"
call "%VSDEVCMD_BAT%" -arch=%VSDEVCMD_ARCH% -host_arch=%VSDEVCMD_ARCH% >nul
if errorlevel 1 exit /b %errorlevel%
set "VCPKG_ROOT=%SALTSCORE_SAVED_VCPKG_ROOT%"
%*
exit /b %errorlevel%
