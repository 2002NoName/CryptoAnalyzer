Param(
    [Parameter(Mandatory = $false)]
    [string]$OutputDir = "test_assets/generated"
)

$ErrorActionPreference = 'Stop'

$repoRoot = (Get-Location).Path
$outFull = Join-Path $repoRoot $OutputDir

Write-Host "Generating test images via WSL2..." -ForegroundColor Cyan
Write-Host "Output: $outFull"

# Ensure output directory exists on Windows side
New-Item -ItemType Directory -Force -Path $outFull | Out-Null

# Run the generator inside WSL. We pass a Linux path under /mnt/<drive>/...
$drive = $repoRoot.Substring(0, 1).ToLowerInvariant()
$rest = $repoRoot.Substring(2) -replace '\\', '/'
$linuxRepoRoot = "/mnt/$drive/$rest"

$linuxOutDir = "$linuxRepoRoot/$OutputDir"

$cmd = "bash '$linuxRepoRoot/test_assets/wsl/generate_images.sh' '$linuxOutDir'"

wsl.exe -- bash -lc $cmd

Write-Host "Done." -ForegroundColor Green
Write-Host "Generated: $OutputDir/multi_volume.img"