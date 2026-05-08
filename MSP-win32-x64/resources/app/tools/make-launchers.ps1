$ErrorActionPreference = "Stop"

$appDir = Split-Path -Parent $PSScriptRoot
$distDir = Resolve-Path (Join-Path $appDir "..\..")
$playerExe = Join-Path $distDir "MSP.exe"
$debugExe = Join-Path $distDir "MSP-Debug.exe"

if (!(Test-Path $playerExe)) {
    throw "Missing player launcher: $playerExe"
}

Copy-Item -LiteralPath $playerExe -Destination $debugExe -Force
Write-Host "Created player launcher: $playerExe"
Write-Host "Created debug launcher:  $debugExe"
