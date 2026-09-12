@echo off
REM build flashfix.exe -- adjust the compiler line to whichever you have
where zig >nul 2>nul && ( zig cc -O2 flashfix.c -o flashfix.exe -lws2_32 -liphlpapi & goto done )
where cl  >nul 2>nul && ( cl /nologo /O2 flashfix.c /Fe:flashfix.exe ws2_32.lib iphlpapi.lib & goto done )
where gcc >nul 2>nul && ( gcc -O2 flashfix.c -o flashfix.exe -lws2_32 -liphlpapi & goto done )
echo No compiler found (zig / cl / gcc).
:done
