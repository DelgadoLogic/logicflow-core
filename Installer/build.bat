@echo off
setlocal

set "TARGET=%~1"
if "%TARGET%"=="" set "TARGET=all"

set "RAW_ARCH=%~2"
if "%RAW_ARCH%"=="" set "RAW_ARCH=x64"
set "ARCH=x64"
set "LINK_MACHINE=X64"
set "VCVARS_BAT=vcvars64.bat"

if /I "%RAW_ARCH%"=="x86" (
    set "ARCH=x86"
    set "LINK_MACHINE=X86"
    set "VCVARS_BAT=vcvarsamd64_x86.bat"
) else if /I "%RAW_ARCH%"=="win-x86" (
    set "ARCH=x86"
    set "LINK_MACHINE=X86"
    set "VCVARS_BAT=vcvarsamd64_x86.bat"
) else if /I "%RAW_ARCH%"=="arm64" (
    set "ARCH=arm64"
) else if /I "%RAW_ARCH%"=="win-arm64" (
    set "ARCH=arm64"
)

if /I "%ARCH%"=="arm64" (
    if exist "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsamd64_arm64.bat" (
        set "VCVARS_BAT=vcvarsamd64_arm64.bat"
        set "LINK_MACHINE=ARM64"
    ) else if exist "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsamd64_arm64.bat" (
        set "VCVARS_BAT=vcvarsamd64_arm64.bat"
        set "LINK_MACHINE=ARM64"
    ) else if exist "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvarsamd64_arm64.bat" (
        set "VCVARS_BAT=vcvarsamd64_arm64.bat"
        set "LINK_MACHINE=ARM64"
    ) else if exist "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvarsamd64_arm64.bat" (
        set "VCVARS_BAT=vcvarsamd64_arm64.bat"
        set "LINK_MACHINE=ARM64"
    )
)

if exist "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\%VCVARS_BAT%" (
    call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\%VCVARS_BAT%" >nul 2>&1
) else if exist "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\%VCVARS_BAT%" (
    call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\%VCVARS_BAT%" >nul 2>&1
) else if exist "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\%VCVARS_BAT%" (
    call "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\%VCVARS_BAT%" >nul 2>&1
) else if exist "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\%VCVARS_BAT%" (
    call "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\%VCVARS_BAT%" >nul 2>&1
)

set "IDIR=%~dp0"
set "SRC=%IDIR%src"
set "BIN=%IDIR%bin"
set "OBJ=%IDIR%obj"
set "LIBS=gdiplus.lib shell32.lib shlwapi.lib user32.lib gdi32.lib ole32.lib kernel32.lib advapi32.lib wininet.lib dwmapi.lib msimg32.lib comdlg32.lib"

if not exist "%BIN%" mkdir "%BIN%"
if not exist "%OBJ%" mkdir "%OBJ%"

if /I not "%TARGET%"=="all" if /I not "%TARGET%"=="uninstaller" if /I not "%TARGET%"=="installer" (
    echo ERROR: Unknown build target "%TARGET%". Expected: all ^| uninstaller ^| installer
    exit /b 1
)

if /I "%TARGET%"=="all" goto :BUILD_UNINSTALLER
if /I "%TARGET%"=="uninstaller" goto :BUILD_UNINSTALLER
if /I "%TARGET%"=="installer" goto :BUILD_INSTALLER

:BUILD_UNINSTALLER
echo [Uninstaller 1/3] Uninstaller resource compile (%ARCH%)...
rc.exe /nologo /fo "%OBJ%\LogicFlowUninstaller.res" "%SRC%\LogicFlowUninstaller.rc"
if errorlevel 1 ( echo UNINSTALLER RC FAILED & exit /b 1 )

echo [Uninstaller 2/3] Uninstaller C++ compile (%ARCH%)...
cl.exe /nologo /W3 /O2 /std:c++17 /EHsc /utf-8 /DUNICODE /D_UNICODE /DWIN32 /DNDEBUG /DLOGICFLOW_UNINSTALLER_ONLY /Fo"%OBJ%\LogicFlowUninstaller.obj" /c "%SRC%\LogicFlowInstaller.cpp"
if errorlevel 1 ( echo UNINSTALLER CL FAILED & exit /b 1 )

echo [Uninstaller 3/3] Uninstaller link (/MACHINE:%LINK_MACHINE%)...
link.exe /nologo /SUBSYSTEM:WINDOWS /MACHINE:%LINK_MACHINE% /OUT:"%BIN%\UninstallLogicFlow.exe" "%OBJ%\LogicFlowUninstaller.obj" "%OBJ%\LogicFlowUninstaller.res" %LIBS%
if errorlevel 1 ( echo UNINSTALLER LINK FAILED & exit /b 1 )

if /I "%TARGET%"=="uninstaller" goto :DONE

:BUILD_INSTALLER
if not exist "%BIN%\UninstallLogicFlow.exe" (
    echo ERROR: %BIN%\UninstallLogicFlow.exe not found. Build target 'uninstaller' before 'installer'.
    exit /b 1
)
if not exist "%IDIR%staging\LogicFlowPayload.zip" (
    echo ERROR: %IDIR%staging\LogicFlowPayload.zip not found. Stage payload zip before building 'installer'.
    exit /b 1
)

echo [Installer 1/3] Installer resource compile (%ARCH%)...
rc.exe /nologo /fo "%OBJ%\LogicFlowInstaller.res" "%SRC%\LogicFlowInstaller.rc"
if errorlevel 1 ( echo INSTALLER RC FAILED & exit /b 1 )

echo [Installer 2/3] Installer C++ compile (%ARCH%)...
cl.exe /nologo /W3 /O2 /std:c++17 /EHsc /utf-8 /DUNICODE /D_UNICODE /DWIN32 /DNDEBUG /Fo"%OBJ%\LogicFlowInstaller.obj" /c "%SRC%\LogicFlowInstaller.cpp"
if errorlevel 1 ( echo INSTALLER CL FAILED & exit /b 1 )

echo [Installer 3/3] Installer link (/MACHINE:%LINK_MACHINE%)...
link.exe /nologo /SUBSYSTEM:WINDOWS /MACHINE:%LINK_MACHINE% /OUT:"%BIN%\LogicFlowSetup.exe" "%OBJ%\LogicFlowInstaller.obj" "%OBJ%\LogicFlowInstaller.res" %LIBS%
if errorlevel 1 ( echo INSTALLER LINK FAILED & exit /b 1 )

:DONE
echo.
echo =================================================================
echo  BUILD SUCCESS (target: %TARGET%, arch: %ARCH%, machine: %LINK_MACHINE%):
if /I not "%TARGET%"=="installer" echo    Uninstaller: %BIN%\UninstallLogicFlow.exe
if /I not "%TARGET%"=="uninstaller" echo    Installer:   %BIN%\LogicFlowSetup.exe
echo =================================================================
exit /b 0
