# ============================================================
# MEDIA CENTER - TEST E2E REALI COMPLETI (ZERO MOCK)
# ============================================================

$ErrorActionPreference = "Stop"
$API = "http://localhost:8000"

Write-Host ""
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "  MEDIA CENTER - TEST E2E REALI (ZERO MOCK)" -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host ""

$passed = 0
$failed = 0

# ============================================================
# 1. BACKEND HEALTH CHECK
# ============================================================
Write-Host "[1/5] Backend Health Check" -ForegroundColor Yellow

try {
    $health = Invoke-WebRequest -Uri "$API/health" -UseBasicParsing -TimeoutSec 5
    Write-Host "  ✅ Backend raggiungibile" -ForegroundColor Green
    $passed++
}
catch {
    Write-Host "  ❌ BACKEND NON RAGGIUNGIBILE!" -ForegroundColor Red
    Write-Host ""
    Write-Host "  Avvia il backend con:" -ForegroundColor Yellow
    Write-Host "  cd backend" -ForegroundColor Gray
    Write-Host "  .\venv\Scripts\Activate.ps1" -ForegroundColor Gray
    Write-Host "  python seed_database.py" -ForegroundColor Gray
    Write-Host "  uvicorn main:app --reload --port 8000" -ForegroundColor Gray
    exit 1
}

# ============================================================
# 2. AUTH TESTS
# ============================================================
Write-Host ""
Write-Host "[2/5] Auth Tests" -ForegroundColor Yellow

# Login FREE
$loginBody = @{
    email = "giulia.bianchi@example.com"
    password = "Test123!"
} | ConvertTo-Json

try {
    $loginResponse = Invoke-RestMethod -Uri "$API/api/v1/auth/login" -Method POST -Body $loginBody -ContentType "application/json"
    if ($loginResponse.access_token -and $loginResponse.user.subscription_tier -eq "FREE") {
        Write-Host "  ✅ Login utente FREE" -ForegroundColor Green
        $passed++
        $freeToken = $loginResponse.access_token
    } else {
        Write-Host "  ❌ Login FREE - dati incompleti" -ForegroundColor Red
        $failed++
    }
} catch {
    Write-Host "  ❌ Login FREE FALLITO: $($_.Exception.Message)" -ForegroundColor Red
    $failed++
}

# Login PREMIUM
$loginPremiumBody = @{
    email = "mario.rossi@example.com"
    password = "Test123!"
} | ConvertTo-Json

try {
    $premiumResponse = Invoke-RestMethod -Uri "$API/api/v1/auth/login" -Method POST -Body $loginPremiumBody -ContentType "application/json"
    if ($premiumResponse.user.subscription_tier -eq "PREMIUM") {
        Write-Host "  ✅ Login utente PREMIUM" -ForegroundColor Green
        $passed++
    }
} catch {
    Write-Host "  ❌ Login PREMIUM FALLITO" -ForegroundColor Red
    $failed++
}

# Login password sbagliata
$badLoginBody = @{
    email = "giulia.bianchi@example.com"
    password = "SBAGLIATA"
} | ConvertTo-Json

try {
    Invoke-RestMethod -Uri "$API/api/v1/auth/login" -Method POST -Body $badLoginBody -ContentType "application/json" -ErrorAction Stop
    Write-Host "  ❌ Login password sbagliata NON ha ritornato 401" -ForegroundColor Red
    $failed++
} catch {
    if ($_.Exception.Response.StatusCode.value__ -eq 401) {
        Write-Host "  ✅ Login password sbagliata = 401" -ForegroundColor Green
        $passed++
    } else {
        Write-Host "  ❌ Errore inaspettato: $($_.Exception.Message)" -ForegroundColor Red
        $failed++
    }
}

# ============================================================
# 3. PAUSE ADS TESTS
# ============================================================
Write-Host ""
Write-Host "[3/5] Pause Ads Tests" -ForegroundColor Yellow

if ($freeToken) {
    $authHeaders = @{ "Authorization" = "Bearer $freeToken" }
    
    try {
        $adResponse = Invoke-RestMethod -Uri "$API/api/v1/ads/pause-ad?user_tier=FREE&video_id=test" -Headers $authHeaders
        if ($adResponse.sponsor_ad) {
            Write-Host "  ✅ GET pause-ad ritorna sponsor ad" -ForegroundColor Green
            Write-Host "     Ad: $($adResponse.sponsor_ad.title)" -ForegroundColor Gray
            $passed++
            $adId = $adResponse.sponsor_ad.id
        } else {
            Write-Host "  ❌ Nessun sponsor_ad" -ForegroundColor Red
            $failed++
        }
    } catch {
        Write-Host "  ❌ GET pause-ad FALLITO: $($_.Exception.Message)" -ForegroundColor Red
        $failed++
    }
    
    # Test impression
    if ($adId) {
        $impressionBody = @{
            ad_id = $adId
            video_id = "test-video-123"
        } | ConvertTo-Json
        
        try {
            $impResponse = Invoke-RestMethod -Uri "$API/api/v1/ads/pause-ad/impression" -Method POST -Headers $authHeaders -Body $impressionBody -ContentType "application/json"
            Write-Host "  ✅ POST impression" -ForegroundColor Green
            $passed++
        } catch {
            Write-Host "  ❌ POST impression FALLITO" -ForegroundColor Red
            $failed++
        }
        
        # Test click
        $clickBody = @{
            ad_id = $adId
            click_type = "sponsor"
        } | ConvertTo-Json
        
        try {
            $clickResponse = Invoke-RestMethod -Uri "$API/api/v1/ads/pause-ad/click" -Method POST -Headers $authHeaders -Body $clickBody -ContentType "application/json"
            Write-Host "  ✅ POST click" -ForegroundColor Green
            $passed++
        } catch {
            Write-Host "  ❌ POST click FALLITO" -ForegroundColor Red
            $failed++
        }
    }
} else {
    Write-Host "  ⏭️ Skipped (no auth token)" -ForegroundColor Gray
}

# ============================================================
# 4. MULTI-USER TESTS
# ============================================================
Write-Host ""
Write-Host "[4/5] Multi-User Tests" -ForegroundColor Yellow

$testUsers = @(
    @{ email = "luca.verdi@example.com"; name = "HYBRID" },
    @{ email = "admin@mediacenter.it"; name = "ADMIN" }
)

foreach ($user in $testUsers) {
    $userBody = @{
        email = $user.email
        password = "Test123!"
    } | ConvertTo-Json
    
    try {
        $userResponse = Invoke-RestMethod -Uri "$API/api/v1/auth/login" -Method POST -Body $userBody -ContentType "application/json"
        Write-Host "  ✅ Login $($user.name)" -ForegroundColor Green
        $passed++
    } catch {
        Write-Host "  ❌ Login $($user.name) FALLITO" -ForegroundColor Red
        $failed++
    }
}

# ============================================================
# 5. PERFORMANCE TEST
# ============================================================
Write-Host ""
Write-Host "[5/5] Performance Test" -ForegroundColor Yellow

$times = @()
for ($i = 0; $i -lt 5; $i++) {
    $start = Get-Date
    Invoke-WebRequest -Uri "$API/health" -UseBasicParsing | Out-Null
    $times += ((Get-Date) - $start).TotalMilliseconds
}
$avgTime = [math]::Round(($times | Measure-Object -Average).Average, 2)

Write-Host "  Health check avg: ${avgTime}ms" -NoNewline
if ($avgTime -lt 100) {
    Write-Host " ✅ PASS" -ForegroundColor Green
    $passed++
} else {
    Write-Host " ⚠️ SLOW (>100ms)" -ForegroundColor Yellow
}

# ============================================================
# RISULTATI
# ============================================================
Write-Host ""
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "  RISULTATI" -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  ✅ Passed: $passed" -ForegroundColor Green
Write-Host "  ❌ Failed: $failed" -ForegroundColor Red
Write-Host ""

$total = $passed + $failed
$passRate = if ($total -gt 0) { [math]::Round(($passed / $total) * 100, 1) } else { 0 }

Write-Host "  Pass Rate: $passRate%" -ForegroundColor $(if ($passRate -ge 95) { "Green" } elseif ($passRate -ge 80) { "Yellow" } else { "Red" })
Write-Host ""

if ($failed -eq 0) {
    Write-Host "  🎉 TUTTI I TEST PASSATI!" -ForegroundColor Green
    exit 0
} else {
    Write-Host "  ⚠️ ALCUNI TEST FALLITI - Verifica sopra" -ForegroundColor Yellow
    exit 1
}
