# =============================================================================
# RUN_TESTS.PS1 - Script Avvio Test con Backend Automatico
# =============================================================================
<#
.SYNOPSIS
    Avvia il backend FastAPI e esegue i test di integrazione.

.DESCRIPTION
    Questo script:
    1. Avvia il backend FastAPI in background
    2. Attende che sia pronto (health check)
    3. Esegue pytest con i parametri specificati
    4. Ferma il backend al termine

    ZERO MOCK POLICY: Tutti i test chiamano backend reale.

.PARAMETER TestPath
    Path dei test da eseguire (default: tests/integration)

.PARAMETER Verbose
    Abilita output verboso (-v per pytest)

.PARAMETER Coverage
    Abilita coverage report

.PARAMETER Marker
    Marker pytest da usare (default: integration)

.EXAMPLE
    .\scripts\run_tests.ps1
    .\scripts\run_tests.ps1 -TestPath "tests/integration/test_fusion_api.py"
    .\scripts\run_tests.ps1 -Verbose -Coverage
    .\scripts\run_tests.ps1 -Marker "integration"
#>

param(
    [string]$TestPath = "tests/integration",
    [switch]$Verbose,
    [switch]$Coverage,
    [string]$Marker = "integration",
    [int]$Timeout = 60
)

# Configurazione
$BACKEND_HOST = "localhost"
$BACKEND_PORT = 8000
$HEALTH_URL = "http://${BACKEND_HOST}:${BACKEND_PORT}/health"
$PROJECT_ROOT = Split-Path -Parent $PSScriptRoot

Write-Host ""
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host " MEDIA CENTER ARTI MARZIALI - Test Runner" -ForegroundColor Cyan
Write-Host " ZERO MOCK POLICY - Real HTTP Tests Only" -ForegroundColor Yellow
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host ""

# Cambia nella directory del progetto
Set-Location $PROJECT_ROOT
Write-Host "[1/5] Directory progetto: $PROJECT_ROOT" -ForegroundColor Yellow

# Verifica se il backend e' gia' attivo
function Test-BackendHealth {
    try {
        $response = Invoke-WebRequest -Uri $HEALTH_URL -TimeoutSec 5 -UseBasicParsing -ErrorAction Stop
        return $response.StatusCode -eq 200
    }
    catch {
        return $false
    }
}

# Verifica se e' gia' attivo
Write-Host "[2/5] Verifico se backend e' gia' attivo..." -ForegroundColor Yellow
$backendAlreadyRunning = Test-BackendHealth

if ($backendAlreadyRunning) {
    Write-Host "Backend gia' attivo su $HEALTH_URL" -ForegroundColor Green
    $backendProcess = $null
}
else {
    Write-Host "[3/5] Avvio backend FastAPI..." -ForegroundColor Yellow

    # Crea directory logs se non esiste
    if (-not (Test-Path "logs")) {
        New-Item -ItemType Directory -Path "logs" -Force | Out-Null
    }

    # Avvia il backend in background
    $backendProcess = Start-Process -FilePath "python" `
        -ArgumentList "-m", "uvicorn", "main:app", "--host", $BACKEND_HOST, "--port", $BACKEND_PORT `
        -PassThru -NoNewWindow -RedirectStandardOutput "logs\backend_stdout.log" -RedirectStandardError "logs\backend_stderr.log"

    Write-Host "Backend PID: $($backendProcess.Id)" -ForegroundColor Gray

    # Attendi che il backend sia pronto
    Write-Host "[4/5] Attendo che backend sia pronto (max ${Timeout}s)..." -ForegroundColor Yellow

    $elapsed = 0
    $ready = $false

    while ($elapsed -lt $Timeout) {
        Start-Sleep -Seconds 2
        $elapsed += 2

        if (Test-BackendHealth) {
            $ready = $true
            break
        }

        Write-Host "  Attesa... ($elapsed s)" -ForegroundColor Gray
    }

    if (-not $ready) {
        Write-Host "ERRORE: Backend non pronto dopo ${Timeout}s" -ForegroundColor Red
        Write-Host "Controlla logs/backend_stderr.log per errori" -ForegroundColor Red

        if ($backendProcess -and -not $backendProcess.HasExited) {
            Stop-Process -Id $backendProcess.Id -Force
        }

        exit 1
    }

    Write-Host "Backend pronto!" -ForegroundColor Green
}

# Costruisci comando pytest
$pytestArgs = @($TestPath)

if ($Verbose) {
    $pytestArgs += "-v"
}

if ($Coverage) {
    $pytestArgs += "--cov=."
    $pytestArgs += "--cov-report=html"
    $pytestArgs += "--cov-report=term-missing"
}

# Aggiungi marker se specificato
if ($Marker) {
    $pytestArgs += "-m"
    $pytestArgs += $Marker
}

Write-Host ""
Write-Host "[5/5] Eseguo test: pytest $($pytestArgs -join ' ')" -ForegroundColor Yellow
Write-Host "---------------------------------------------" -ForegroundColor Cyan

# Esegui pytest
$testResult = 0
try {
    & python -m pytest @pytestArgs
    $testResult = $LASTEXITCODE
}
catch {
    Write-Host "Errore durante esecuzione test: $_" -ForegroundColor Red
    $testResult = 1
}

Write-Host "---------------------------------------------" -ForegroundColor Cyan

# Ferma il backend se lo abbiamo avviato noi
if ($backendProcess -and -not $backendProcess.HasExited) {
    Write-Host ""
    Write-Host "Fermo backend (PID: $($backendProcess.Id))..." -ForegroundColor Yellow
    Stop-Process -Id $backendProcess.Id -Force
    Write-Host "Backend fermato." -ForegroundColor Green
}

# Risultato finale
Write-Host ""
if ($testResult -eq 0) {
    Write-Host "=============================================" -ForegroundColor Green
    Write-Host " TUTTI I TEST PASSATI!" -ForegroundColor Green
    Write-Host "=============================================" -ForegroundColor Green
}
else {
    Write-Host "=============================================" -ForegroundColor Red
    Write-Host " ALCUNI TEST FALLITI (exit code: $testResult)" -ForegroundColor Red
    Write-Host "=============================================" -ForegroundColor Red
}

exit $testResult
