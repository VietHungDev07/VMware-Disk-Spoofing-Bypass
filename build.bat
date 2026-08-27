@echo off
REM ============================================================================
REM AceSpyDrv.sys build script — supplementary disk IOCTL hook driver
REM Requires: Visual Studio 2022 + WDK 10.0.28000.0 (or compatible)
REM ============================================================================

setlocal enabledelayedexpansion

REM --- Find Visual Studio vcvars64.bat ---
set "VCVARS=C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat"
if not exist "%VCVARS%" set "VCVARS=C:\Program Files\Microsoft Visual Studio\17\Community\VC\Auxiliary\Build\vcvars64.bat"
if not exist "%VCVARS%" set "VCVARS=C:\Program Files\Microsoft Visual Studio\17\Professional\VC\Auxiliary\Build\vcvars64.bat"
if not exist "%VCVARS%" set "VCVARS=C:\Program Files\Microsoft Visual Studio\17\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
if not exist "%VCVARS%" (
    echo FAILED: Cannot find vcvars64.bat
    exit /b 1
)

call "%VCVARS%" >nul 2>&1

REM --- Find WDK ---
set "WDK_INC=C:\Program Files (x86)\Windows Kits\10\Include\10.0.28000.0"
set "WDK_LIB=C:\Program Files (x86)\Windows Kits\10\Lib\10.0.28000.0"
if not exist "%WDK_INC%\km" (
    REM Try 26100
    set "WDK_INC=C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0"
    set "WDK_LIB=C:\Program Files (x86)\Windows Kits\10\Lib\10.0.26100.0"
)
if not exist "%WDK_INC%\km" (
    echo FAILED: Cannot find WDK include directory
    exit /b 1
)

echo === WDK: %WDK_INC% ===
echo === Building AceSpyDrv.sys ===

cd /d "%~dp0"

REM --- Compile AceSpyDrv.cpp ---
cl /nologo /c /kernel /O2 /W3 /GS- /Zl /Gy ^
    /D_AMD64_ /D_WIN64 /DAMD64 /D_KERNEL_MODE /DNT /D_WIN32_WINNT=0x0A00 ^
    /D_WINNT_WIN32=0x0A00 /DKMDF_VERSION_MAJOR=1 /DKMDF_VERSION_MINOR=33 ^
    /I"%WDK_INC%\km" /I"%WDK_INC%\km\crt" /I"%WDK_INC%\shared" ^
    /I"%WDK_INC%\um" ^
    AceSpyDrv.cpp

if errorlevel 1 (
    echo FAILED: cl.exe returned %errorlevel%
    exit /b 1
)

REM --- Link AceSpyDrv.sys ---
link /nologo /SUBSYSTEM:NATIVE /DRIVER /MACHINE:X64 ^
    /ENTRY:DriverEntry ^
    /NODEFAULTLIB ^
    /LIBPATH:"%WDK_LIB%\km\x64" ^
    /LIBPATH:"%WDK_LIB%\km\x64\${OVERRIDE}" ^
    ntoskrnl.lib hal.lib BufferOverflowFastFailK.lib wmilib.lib ^
    /OUT:AceSpyDrv.sys ^
    AceSpyDrv.obj

if errorlevel 1 (
    echo FAILED: link.exe returned %errorlevel%
    exit /b 1
)

REM --- Sign the driver (test signing) ---
REM Create a self-signed test certificate if not exists
if not exist AceSpyTestCert.pfx (
    echo === Creating test certificate ===
    powershell -Command "$cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject 'CN=AceSpy Test' -KeyUsage DigitalSignature -FriendlyName 'AceSpy Test Cert' -CertStoreLocation 'Cert:\CurrentUser\My' -KeyExportPolicy Exportable -NotAfter (Get-Date).AddYears(3); $pwd = ConvertTo-SecureString -String 'AceSpy123' -Force -AsPlainText; Export-PfxCertificate -Cert $cert -FilePath AceSpyTestCert.pfx -Password $pwd" 2>nul
)

REM Sign with signtool if cert exists
if exist AceSpyTestCert.pfx (
    set "SIGNTOOL=C:\Program Files (x86)\Windows Kits\10\bin\10.0.28000.0\x64\signtool.exe"
    if not exist "!SIGNTOOL!" set "SIGNTOOL=C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe"
    if exist "!SIGNTOOL!" (
        echo === Signing AceSpyDrv.sys ===
        "!SIGNTOOL!" sign /f AceSpyTestCert.pfx /p AceSpy123 /fd SHA256 /v AceSpyDrv.sys 2>nul
        if errorlevel 1 (
            echo [WARN] Signing failed — driver will need test signing mode or manual mapper
        )
    )
)

echo === Build successful ===
dir AceSpyDrv.sys

endlocal
