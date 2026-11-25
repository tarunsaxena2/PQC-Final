# Run from C:\Users\Lenovo\PQC-Final with the venv active:  .\run_week1.ps1
$ErrorActionPreference = "Stop"
Write-Host "== Day 2: interface tests ==" ; python -m pytest tests -q
Write-Host "== Day 3: KEM demo + comparison ==" ; python code/kem_demo.py --write
Write-Host "Done. Open notes\vaibhav\week1\ to see the results."
