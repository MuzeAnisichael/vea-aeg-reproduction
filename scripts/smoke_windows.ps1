$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $repoRoot

$env:PYTHONDONTWRITEBYTECODE = "1"
$env:PYTHONPATH = "src"

python -m vea_aeg dangerous
python -m vea_aeg smoke --json
python -m vea_aeg plan IP_OVERWRITE --json
python -m unittest discover -s tests

