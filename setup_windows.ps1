# setup_windows.ps1
# Run with: .\setup_windows.ps1

Write-Host "🚀 Setting up NeuroShield on Windows..." -ForegroundColor Cyan

# Create directories
$dirs = @("logs", "forensics", "data", "models", "src", "tests", "api", "dashboard")
foreach ($dir in $dirs) {
    if (!(Test-Path $dir)) {
        New-Item -ItemType Directory -Name $dir | Out-Null
        Write-Host "Created: $dir" -ForegroundColor Green
    }
}

# Create virtual environment
if (!(Test-Path "venv")) {
    Write-Host "Creating virtual environment..." -ForegroundColor Yellow
    python -m venv venv
}

# Activate and install
Write-Host "Activating venv and installing dependencies..." -ForegroundColor Yellow
& .\venv\Scripts\python.exe -m pip install --upgrade pip setuptools wheel

# Install requirements one by one to catch failures
$packages = @(
    "numpy>=1.26.0",
    "pandas>=2.1.0", 
    "scikit-learn>=1.3.0",
    "psutil>=5.9.5",
    "fastapi>=0.104.0",
    "uvicorn>=0.24.0",
    "pydantic>=2.5.0",
    "pytest>=7.4.0",
    "httpx>=0.25.0"
)

foreach ($pkg in $packages) {
    Write-Host "Installing $pkg..." -ForegroundColor Cyan
    & .\venv\Scripts\pip.exe install $pkg
    if ($LASTEXITCODE -ne 0) {
        Write-Host "⚠️  Failed to install $pkg - continuing..." -ForegroundColor Red
    }
}

Write-Host "`n✅ Setup complete!" -ForegroundColor Green
Write-Host "Activate with: .\venv\Scripts\Activate.ps1" -ForegroundColor Yellow
Write-Host "Run mock API: .\venv\Scripts\python.exe mock_api.py" -ForegroundColor Yellow