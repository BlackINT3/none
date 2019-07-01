@echo off

echo [+] Initialize...
if exist knone rd /q /s knone
@rem del *.autopkg *.nupkg

echo.
echo [+] Copying...

::CopyFiles
set SOURCE_DIR=%CD%/../src
set CORE_DIR=%SOURCE_DIR%/knone
set PLUGINS_DIR=%SOURCE_DIR%/knone/plugins
set DEST_DIR=%CD%
set COPY_PATTERN=%SOURCE_DIR%;%DEST_DIR%

::Core Library
call unone-tool.exe -copy-file %CORE_DIR%/knone.h %COPY_PATTERN%
call unone-tool.exe -copy-file %CORE_DIR%/native/knone-native.h %COPY_PATTERN%
call unone-tool.exe -copy-file %CORE_DIR%/internal/knone-internal.h %COPY_PATTERN%
call unone-tool.exe -copy-file %CORE_DIR%/os/knone-os.h %COPY_PATTERN%
call unone-tool.exe -copy-file %CORE_DIR%/process/knone-ps.h %COPY_PATTERN%
call unone-tool.exe -copy-file %CORE_DIR%/string/knone-str.h %COPY_PATTERN%
call unone-tool.exe -copy-file %CORE_DIR%/file/knone-fs.h %COPY_PATTERN%
call unone-tool.exe -copy-file %CORE_DIR%/memory/knone-mm.h %COPY_PATTERN%
call unone-tool.exe -copy-file %CORE_DIR%/object/knone-ob.h %COPY_PATTERN%
call unone-tool.exe -copy-file %CORE_DIR%/time/knone-tm.h %COPY_PATTERN%
::Plugins Library

echo.
echo [+] Copy header files completed...

echo.
xcopy /E /Y  "%DEST_DIR%"\bin\*knone*.lib  "%DEST_DIR%"\knone
xcopy /E /Y  "%DEST_DIR%"\bin\*knone*.dll  "%DEST_DIR%"\knone
echo.
echo [+] Copy all files completed...

echo.
echo [+] Nuget packing...
for %%i in (*knone*.autopkg) do (
  powershell Write-NugetPackage %%i -NoSplit -Verbose
)
echo [+] Nuget pack completed...

ping -n 1 127.0.0.1>nul
