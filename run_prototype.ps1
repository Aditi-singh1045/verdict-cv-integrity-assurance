$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
Write-Host "Starting VERDICT - offline local prototype..." -ForegroundColor Cyan
python .\verdict_app.py
