@echo off
setlocal
cd /d "%~dp0"

echo === [1/6] vet + unit tests ===
go vet ./... || goto :fail
go test ./... || goto :fail

echo === [2/6] regenerate app icon (icon.png -^> build\windows\icon.ico) ===
go run .\build\genicon || goto :fail

echo === [3/6] frontend bundle ===
pushd frontend
call npm install || goto :fail
call npm run build || goto :fail
popd

echo === [4/6] Wails GUI build ===
call wails build -clean || goto :fail

echo === [5/6] service binary ===
go build -trimpath -ldflags "-s -w" -o build\bin\mihanisecurity-service.exe .\cmd\mihanisecurity-service || goto :fail

echo === [6/7] sign release binaries ===
powershell -NoProfile -ExecutionPolicy Bypass -File deploy\sign.ps1 || goto :fail

echo === [7/7] installer ===
set "ISCC=%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe"
if not exist "%ISCC%" set "ISCC=C:\Program Files (x86)\Inno Setup 6\ISCC.exe"
if not exist "%ISCC%" (
    echo ISCC.exe not found - install Inno Setup 6 or set ISCC to its path.
    goto :fail
)
call "%ISCC%" installer\MihaniSecurity.iss || goto :fail

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