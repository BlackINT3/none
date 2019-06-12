@echo off

echo [+] Initialize...
if exist unone rd /q /s unone
@rem del *.autopkg *.nupkg

echo.
echo [+] Copying...

::CopyFiles
set SOURCE_DIR=%CD%/../src
set CORE_DIR=%SOURCE_DIR%/unone
set PLUGINS_DIR=%SOURCE_DIR%/unone/plugins
set DEST_DIR=%CD%
set COPY_PATTERN=%SOURCE_DIR%;%DEST_DIR%

::Core Library
call unone-tool.exe -copy-file %CORE_DIR%/unone.h %COPY_PATTERN%
call unone-tool.exe -copy-file %CORE_DIR%/native/unone-native.h %COPY_PATTERN%
call unone-tool.exe -copy-file %CORE_DIR%/internal/unone-internal.h %COPY_PATTERN%
call unone-tool.exe -copy-file %CORE_DIR%/os/unone-os.h %COPY_PATTERN%
call unone-tool.exe -copy-file %CORE_DIR%/process/unone-ps.h %COPY_PATTERN%
call unone-tool.exe -copy-file %CORE_DIR%/string/unone-str.h %COPY_PATTERN%
call unone-tool.exe -copy-file %CORE_DIR%/file/unone-fs.h %COPY_PATTERN%
call unone-tool.exe -copy-file %CORE_DIR%/memory/unone-mm.h %COPY_PATTERN%
call unone-tool.exe -copy-file %CORE_DIR%/pe/unone-pe.h %COPY_PATTERN%
call unone-tool.exe -copy-file %CORE_DIR%/object/unone-ob.h %COPY_PATTERN%
call unone-tool.exe -copy-file %CORE_DIR%/security/unone-se.h %COPY_PATTERN%
call unone-tool.exe -copy-file %CORE_DIR%/time/unone-tm.h %COPY_PATTERN%
call unone-tool.exe -copy-file %CORE_DIR%/network/unone-net.h %COPY_PATTERN%
call unone-tool.exe -copy-file %CORE_DIR%/registry/unone-reg.h %COPY_PATTERN%
call unone-tool.exe -copy-file %CORE_DIR%/plugins/unone-plugins.h %COPY_PATTERN%

::Plugin Library

echo.
echo [+] Copy header files completed...

echo.
xcopy /E /Y  "%DEST_DIR%"\bin\*unone*.lib  "%DEST_DIR%"\unone
xcopy /E /Y  "%DEST_DIR%"\bin\*unone*.dll  "%DEST_DIR%"\unone
echo.
echo [+] Copy all files completed...

echo.
echo [+] Nuget packing...
for %%i in (*.autopkg) do (
  powershell Write-NugetPackage %%i -NoSplit -Verbose
)
echo [+] Nuget pack completed...

ping -n 1 127.0.0.1>nul
