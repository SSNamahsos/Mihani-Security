$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$pfx = Join-Path $PSScriptRoot "mihani-sign.pfx"
$certPw = $env:MIHANI_SIGN_PW
if (-not $certPw) { $certPw = "mihanisec123" }
if (-not (Test-Path $pfx)) {
  Write-Output "SKIP: $pfx not found - binaries left unsigned (public builds)"
  exit 0
}
$sig = "C:\Program Files (x86)\Windows Kits\10\bin\10.0.22621.0\x64\signtool.exe"
if (-not (Test-Path $sig)) {
  $found = Get-ChildItem "C:\Program Files (x86)\Windows Kits\10\bin" -Recurse -Filter signtool.exe -ErrorAction SilentlyContinue | Where-Object { $_.FullName -match "x64" } | Select-Object -First 1 -ExpandProperty FullName
  if (-not $found) {
    Write-Output "SKIP: signtool.exe not found - binaries left unsigned"
    exit 0
  }
  $sig = $found
}
$targets = @(
  (Join-Path $root "build\bin\MihaniSecurity.exe"),
  (Join-Path $root "build\bin\mihanisecurity-service.exe")
)
$setup = Join-Path $root "dist\MihaniSecurity Setup.exe"
if (Test-Path $setup) { $targets += $setup }
foreach ($t in $targets) {
  & $sig sign /f $pfx /p $certPw /fd SHA256 $t 2>&1 | Out-Null
  if ($LASTEXITCODE -ne 0) { Write-Error "signing failed: $t"; exit 1 }
  & $sig verify /pa $t 2>&1 | Out-Null
  if ($LASTEXITCODE -ne 0) { Write-Error "verify failed: $t"; exit 1 }
}
Write-Output "signed: $($targets.Count) binaries (signtool)"