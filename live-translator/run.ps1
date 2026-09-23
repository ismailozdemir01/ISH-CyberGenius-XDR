$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

if (-not (Test-Path .venv)) {
    py -3.11 -m venv .venv
}

& .\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

if (-not (Test-Path .env) -and (Test-Path .env.example)) {
    Copy-Item .env.example .env
    Write-Host 'Created live-translator/.env. Add Azure Translator credentials for full Turkish translation.'
}

python main.py
