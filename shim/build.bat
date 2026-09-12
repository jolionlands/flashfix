@echo off
REM Build flashnet_shim.dll -- the FlashNetwork.dll replacement.
REM Requires MSVC (Visual Studio Build Tools) for ml64 + the x64 CRT.
setlocal

set VSBASE=C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools
call "%VSBASE%\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
if errorlevel 1 (
    echo Could not initialise MSVC. Edit VSBASE in build.bat.
    exit /b 1
)

cd /d "%~dp0"

echo [1/3] generating forwarders...
python tools\gen_forwards.py || goto :err

echo [2/3] compiling...
cl /nologo /LD /O2 /W3 /c flashnet_shim.c /Fo:build\shim.obj || goto :err
ml64 /nologo /c /Fo build\forwards.obj flashnet_forwards.asm || goto :err

echo [3/3] linking...
link /nologo /DLL /OUT:flashnet_shim.dll /DEF:flashnet_shim.def ^
     /IMPLIB:build\flashnet_shim.lib build\shim.obj build\forwards.obj ^
     ws2_32.lib user32.lib ole32.lib advapi32.lib || goto :err

echo.
echo OK -- flashnet_shim.dll built.
exit /b 0

:err
echo.
echo BUILD FAILED
exit /b 1
