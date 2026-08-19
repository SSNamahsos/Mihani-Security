@echo off
setlocal
cd /d "%~dp0"

echo === [1/8] vet + unit tests ===
go vet ./... || goto :fail
go test ./... || goto :fail

echo === [2/8] regenerate app icon (icon.png -^> build\windows\icon.ico) ===
go run .\build\genicon || goto :fail

echo === [3/8] frontend bundle ===
pushd frontend
call npm install || goto :fail
call npm run build || goto :fail
popd

echo === [4/8] Wails GUI build ===
call wails build -clean || goto :fail

echo === [5/8] version resources (go-winres patch) ===
if exist build\windows\winres.json (
    go-winres patch --delete --no-backup --in build\windows\winres.json build\bin\MihaniSecurity.exe || goto :fail
) else (
    echo SKIP: winres.json not found - exe left without version resources
)

echo === [6/8] service binary ===
go build -trimpath -ldflags "-s -w" -o build\bin\mihanisecurity-service.exe .\cmd\mihanisecurity-service || goto :fail

echo === [7/8] installer ===
set "ISCC=%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe"
if not exist "%ISCC%" set "ISCC=C:\Program Files (x86)\Inno Setup 6\ISCC.exe"
if not exist "%ISCC%" (
    echo ISCC.exe not found - install Inno Setup 6 or set ISCC to its path.
    goto :fail
)
call "%ISCC%" installer\MihaniSecurity.iss || goto :fail

echo === [8/8] sign release binaries ===
powershell -NoProfile -ExecutionPolicy Bypass -File deploy\sign.ps1 || goto :fail

echo.
echo BUILD OK:
echo   GUI:      build\bin\MihaniSecurity.exe
echo   Service:  build\bin\mihanisecurity-service.exe
echo   Installer: dist\MihaniSecurity Setup.exe
exit /b 0

:fail
echo.
echo BUILD FAILED - see output above.
exit /b 1
