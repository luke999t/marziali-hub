# Enterprise Test Suite Runner for Windows
# Target: 90%+ coverage, 95%+ pass rate

param(
    [switch]$All,
    [switch]$Unit,
    [switch]$Integration,
    [switch]$Regression,
    [switch]$Security,
    [switch]$Penetration,
    [switch]$Slow,
    [switch]$Coverage,
    [switch]$Report
)

Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║           Enterprise Test Suite - Flutter App                 ║" -ForegroundColor Cyan
Write-Host "║                  Target: 90%+ Coverage, 95%+ Pass Rate       ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Function to run tests with a specific tag
function Run-TestsByTag {
    param(
        [string]$Tag,
        [string]$Name
    )

    Write-Host ""
    Write-Host "▶ Running $Name..." -ForegroundColor Blue
    flutter test --tags=$Tag --reporter=expanded
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✓ $Name completed" -ForegroundColor Green
    } else {
        Write-Host "✗ $Name failed" -ForegroundColor Red
    }
}

# Default: run main test categories if no specific flag
if (-not ($Unit -or $Integration -or $Regression -or $Security -or $Penetration -or $Slow -or $All)) {
    $Unit = $true
    $Integration = $true
    $Regression = $true
    $Security = $true
}

# Run all if specified
if ($All) {
    $Unit = $true
    $Integration = $true
    $Regression = $true
    $Security = $true
    $Penetration = $true
    $Slow = $true
}

# Run test categories
if ($Unit) {
    Run-TestsByTag -Tag "unit" -Name "Unit Tests"
}

if ($Integration) {
    Run-TestsByTag -Tag "integration" -Name "Integration Tests"
}

if ($Regression) {
    Run-TestsByTag -Tag "regression" -Name "Regression Tests"
}

if ($Security) {
    Run-TestsByTag -Tag "security" -Name "Security Tests"
}

if ($Penetration) {
    Run-TestsByTag -Tag "penetration" -Name "Penetration Tests"
}

if ($Slow) {
    Run-TestsByTag -Tag "slow" -Name "Slow Tests (Performance, Holistic)"
}

# Generate coverage report
if ($Coverage) {
    Write-Host ""
    Write-Host "▶ Generating Coverage Report..." -ForegroundColor Blue
    flutter test --coverage

    if (Test-Path "coverage/lcov.info") {
        Write-Host "✓ Coverage data generated at coverage/lcov.info" -ForegroundColor Green

        # Try to generate HTML report if genhtml is available
        $genhtml = Get-Command genhtml -ErrorAction SilentlyContinue
        if ($genhtml) {
            genhtml coverage/lcov.info -o coverage/html
            Write-Host "✓ HTML report generated at coverage/html/index.html" -ForegroundColor Green
        } else {
            Write-Host "⚠ Install lcov/genhtml for HTML coverage report" -ForegroundColor Yellow
        }
    }

    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  Coverage Target: 90%+" -ForegroundColor White
    Write-Host "  Pass Rate Target: 95%+" -ForegroundColor White
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
}

# Generate test report
if ($Report) {
    Write-Host ""
    Write-Host "▶ Generating Test Report..." -ForegroundColor Blue

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $reportFile = "test_report_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"

    $reportContent = @"
═══════════════════════════════════════════════════════════════════════════════
                         ENTERPRISE TEST REPORT
                         Generated: $timestamp
═══════════════════════════════════════════════════════════════════════════════

Test Categories Executed:
- Unit Tests: $Unit
- Integration Tests: $Integration
- Regression Tests: $Regression
- Security Tests: $Security
- Penetration Tests: $Penetration
- Slow Tests: $Slow

Coverage Report: $Coverage

Quality Gates:
- Coverage Target: 90%+
- Pass Rate Target: 95%+

Run 'flutter test' for detailed results.
═══════════════════════════════════════════════════════════════════════════════
"@

    $reportContent | Out-File -FilePath $reportFile -Encoding UTF8
    Write-Host "✓ Report saved to $reportFile" -ForegroundColor Green
}

Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "                     Test Run Complete                          " -ForegroundColor White
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
