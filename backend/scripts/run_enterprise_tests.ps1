# 🎓 AI_MODULE: Enterprise Test Suite Runner
# 🎓 AI_DESCRIPTION: Script per eseguire test suite enterprise per categoria
# 🎓 AI_BUSINESS: Automazione test con report dettagliati
# 🎓 AI_TEACHING: PowerShell script con parametri e output colorato

param(
    [ValidateSet("all", "smoke", "regression", "holistic", "security", "integration", "audit", "quick")]
    [string]$Category = "all",

    [switch]$Coverage,
    [switch]$Verbose,
    [switch]$StopOnFailure
)

$ErrorActionPreference = "Continue"

# Colors
function Write-Title($text) {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  $text" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan
}

function Write-Section($text) {
    Write-Host "`n--- $text ---" -ForegroundColor Yellow
}

function Write-Success($text) {
    Write-Host "[OK] $text" -ForegroundColor Green
}

function Write-Failure($text) {
    Write-Host "[FAIL] $text" -ForegroundColor Red
}

function Write-Info($text) {
    Write-Host "[INFO] $text" -ForegroundColor White
}

# Check if backend is running
function Test-BackendHealth {
    try {
        $response = Invoke-WebRequest -Uri "http://localhost:8000/health" -Method GET -TimeoutSec 5 -ErrorAction SilentlyContinue
        return $response.StatusCode -eq 200
    } catch {
        return $false
    }
}

Write-Title "Enterprise Test Suite - $Category"

# Check backend
Write-Section "Checking Backend Health"
if (Test-BackendHealth) {
    Write-Success "Backend is running at localhost:8000"
} else {
    Write-Failure "Backend is NOT running!"
    Write-Info "Start backend with: uvicorn main:app --reload"
    exit 1
}

# Build pytest args
$baseArgs = @("-v")
if ($StopOnFailure) {
    $baseArgs += "-x"
}
if ($Verbose) {
    $baseArgs += "--tb=long"
} else {
    $baseArgs += "--tb=short"
}

$coverageArgs = @()
if ($Coverage) {
    $coverageArgs = @("--cov=api", "--cov=services", "--cov=models", "--cov-report=term-missing", "--cov-report=html")
}

# Results tracking
$results = @{}

function Run-TestCategory($name, $path, $marker = $null) {
    Write-Section "$name Tests"

    $args = $baseArgs.Clone()
    if ($marker) {
        $args += "-m"
        $args += $marker
    }
    $args += $path

    $startTime = Get-Date

    try {
        & pytest @args
        $exitCode = $LASTEXITCODE
    } catch {
        $exitCode = 1
    }

    $duration = ((Get-Date) - $startTime).TotalSeconds

    $results[$name] = @{
        ExitCode = $exitCode
        Duration = [math]::Round($duration, 2)
        Status = if ($exitCode -eq 0) { "PASS" } else { "FAIL" }
    }

    if ($exitCode -eq 0) {
        Write-Success "$name completed in $($results[$name].Duration)s"
    } else {
        Write-Failure "$name failed (exit code: $exitCode)"
        if ($StopOnFailure) {
            Write-Info "Stopping due to -StopOnFailure flag"
            exit 1
        }
    }

    return $exitCode
}

switch ($Category) {
    "smoke" {
        Run-TestCategory "Smoke" "tests/smoke/" "smoke"
    }

    "regression" {
        Run-TestCategory "Regression" "tests/regression/" "regression"
    }

    "holistic" {
        Run-TestCategory "Holistic" "tests/holistic/" "holistic"
    }

    "security" {
        Run-TestCategory "Security" "tests/security/" "security"
    }

    "integration" {
        Run-TestCategory "Integration" "tests/integration/" "integration"
    }

    "audit" {
        Run-TestCategory "Audit" "tests/audit/" "audit"
    }

    "quick" {
        # Quick = smoke + regression only
        Run-TestCategory "Smoke" "tests/smoke/" "smoke"
        Run-TestCategory "Regression" "tests/regression/" "regression"
    }

    "all" {
        # Full enterprise suite in order of importance
        Write-Title "Running Full Enterprise Test Suite"

        # 1. Smoke tests first (if these fail, don't continue)
        Write-Section "PHASE 1: Smoke Tests"
        $smokeResult = Run-TestCategory "Smoke" "tests/smoke/" "smoke"
        if ($smokeResult -ne 0) {
            Write-Failure "Smoke tests failed - system not ready"
            Write-Info "Fix smoke test failures before proceeding"
            # Continue anyway to get full report
        }

        # 2. Regression tests
        Write-Section "PHASE 2: Regression Tests"
        Run-TestCategory "Regression" "tests/regression/" "regression"

        # 3. Unit tests
        Write-Section "PHASE 3: Unit Tests"
        Run-TestCategory "Unit" "tests/unit/" "unit"

        # 4. Integration tests
        Write-Section "PHASE 4: Integration Tests"
        Run-TestCategory "Integration" "tests/integration/" "integration"

        # 5. Holistic tests
        Write-Section "PHASE 5: Holistic Tests"
        Run-TestCategory "Holistic" "tests/holistic/" "holistic"

        # 6. Audit tests
        Write-Section "PHASE 6: Audit Tests"
        Run-TestCategory "Audit" "tests/audit/" "audit"

        # 7. Security tests (optional, may be slow)
        Write-Section "PHASE 7: Security Tests"
        Run-TestCategory "Security" "tests/security/" "security"

        # Final coverage report
        if ($Coverage) {
            Write-Section "PHASE 8: Coverage Report"
            & pytest @coverageArgs tests/
        }
    }
}

# Summary
Write-Title "Test Results Summary"

$totalTests = $results.Count
$passedTests = ($results.Values | Where-Object { $_.Status -eq "PASS" }).Count
$failedTests = $totalTests - $passedTests
$totalTime = ($results.Values | ForEach-Object { $_.Duration } | Measure-Object -Sum).Sum

Write-Host "`nCategory Results:" -ForegroundColor White
Write-Host "----------------" -ForegroundColor White

foreach ($key in $results.Keys) {
    $result = $results[$key]
    $color = if ($result.Status -eq "PASS") { "Green" } else { "Red" }
    Write-Host ("  {0,-15} {1,-6} ({2}s)" -f $key, $result.Status, $result.Duration) -ForegroundColor $color
}

Write-Host "`nOverall:" -ForegroundColor White
Write-Host "  Total Categories: $totalTests" -ForegroundColor White
Write-Host "  Passed: $passedTests" -ForegroundColor Green
Write-Host "  Failed: $failedTests" -ForegroundColor $(if ($failedTests -gt 0) { "Red" } else { "Green" })
Write-Host "  Total Time: $([math]::Round($totalTime, 2))s" -ForegroundColor White

# Pass rate
if ($totalTests -gt 0) {
    $passRate = [math]::Round(($passedTests / $totalTests) * 100, 1)
    $passRateColor = if ($passRate -ge 95) { "Green" } elseif ($passRate -ge 80) { "Yellow" } else { "Red" }
    Write-Host "`n  Pass Rate: $passRate%" -ForegroundColor $passRateColor

    if ($passRate -lt 95) {
        Write-Host "  Target: 95%" -ForegroundColor Yellow
    }
}

# Exit code based on results
if ($failedTests -gt 0) {
    exit 1
} else {
    Write-Host "`n All tests passed!" -ForegroundColor Green
    exit 0
}
