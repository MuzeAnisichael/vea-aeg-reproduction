$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $repoRoot

$env:PYTHONDONTWRITEBYTECODE = "1"
$env:PYTHONPATH = "src"

python -m vea_aeg dangerous
python -m vea_aeg smoke --json
if (Test-Path "C:\Windows\System32\notepad.exe") {
  python -m vea_aeg inventory "C:\Windows\System32\notepad.exe" --backend basic --json
}
python -m vea_aeg plan IP_OVERWRITE --json
python -m vea_aeg experiment
python -m unittest discover -s tests
