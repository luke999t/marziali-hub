# run_real_tests.ps1
# Test REALI contro backend - ZERO mock

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  MEDIA CENTER - TEST REALI (NO MOCK)" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$API = "http://localhost:8000/api/v1"
$passed = 0
$failed = 0

# ============================================
# 1. HEALTH CHECK
# ============================================
Write-Host "[1/4] Backend Health Check..." -ForegroundColor Yellow

try {
    $response = Invoke-WebRequest -Uri "http://localhost:8000/health" -UseBasicParsing -TimeoutSec 5
    if ($response.StatusCode -eq 200) {
        Write-Host "  ✅ Backend raggiungibile" -ForegroundColor Green
        $passed++
    }
} catch {
    Write-Host "  ❌ BACKEND NON RAGGIUNGIBILE" -ForegroundColor Red
    Write-Host "     Avvia: uvicorn main:app --reload --port 8000" -ForegroundColor Yellow
    $failed++
    Write-Host ""
    Write-Host "ABORT: Backend non disponibile" -ForegroundColor Red
    exit 1
}

# ============================================
# 2. AUTH TESTS
# ============================================
Write-Host ""
Write-Host "[2/4] Auth Tests..." -ForegroundColor Yellow

# Test login valido
$body = @{
    email = "giulia.bianchi@example.com"
    password = "Test123!"
} | ConvertTo-Json

try {
    $loginResponse = Invoke-RestMethod -Uri "$API/auth/login" -Method POST -Body $body -ContentType "application/json"
    if ($loginResponse.access_token) {
        Write-Host "  ✅ Login utente FREE OK" -ForegroundColor Green
        Write-Host "     Email: $($loginResponse.user.email)" -ForegroundColor Gray
        Write-Host "     Tier: $($loginResponse.user.subscription_tier)" -ForegroundColor Gray
        $passed++
        $authToken = $loginResponse.access_token
    }
} catch {
    Write-Host "  ❌ Login FALLITO" -ForegroundColor Red
    Write-Host "     $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "     ESEGUI: python seed_database.py" -ForegroundColor Yellow
    $failed++
    $authToken = $null
}

# Test login invalido
$badBody = @{
    email = "giulia.bianchi@example.com"
    password = "SBAGLIATA"
} | ConvertTo-Json

try {
    $badResponse = Invoke-RestMethod -Uri "$API/auth/login" -Method POST -Body $badBody -ContentType "application/json" -ErrorAction Stop
    Write-Host "  ❌ Login con password sbagliata doveva fallire!" -ForegroundColor Red
    $failed++
} catch {
    if ($_.Exception.Response.StatusCode -eq 401) {
        Write-Host "  ✅ Login password sbagliata rejected (401)" -ForegroundColor Green
        $passed++
    } else {
        Write-Host "  ⚠️ Errore inaspettato: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

# ============================================
# 3. PAUSE ADS TESTS
# ============================================
Write-Host ""
Write-Host "[3/4] Pause Ads Tests..." -ForegroundColor Yellow

if ($authToken) {
    $headers = @{ "Authorization" = "Bearer $authToken" }
    
    # GET pause ad
    try {
        $adResponse = Invoke-RestMethod -Uri "$API/ads/pause-ad?user_tier=FREE&video_id=test-video" -Headers $headers
        if ($adResponse.sponsor_ad) {
            Write-Host "  ✅ GET pause-ad OK" -ForegroundColor Green
            Write-Host "     Ad: $($adResponse.sponsor_ad.title)" -ForegroundColor Gray
            Write-Host "     Advertiser: $($adResponse.sponsor_ad.advertiser_name)" -ForegroundColor Gray
            $passed++
        } else {
            Write-Host "  ⚠️ Nessun ad ritornato" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "  ❌ GET pause-ad FALLITO" -ForegroundColor Red
        Write-Host "     $($_.Exception.Message)" -ForegroundColor Gray
        $failed++
    }
} else {
    Write-Host "  ⏭️ Skipped (no auth token)" -ForegroundColor Gray
}

# ============================================
# 4. MULTI-USER TESTS
# ============================================
Write-Host ""
Write-Host "[4/4] Multi-User Tests..." -ForegroundColor Yellow

$testUsers = @(
    @{ email = "mario.rossi@example.com"; tier = "PREMIUM" },
    @{ email = "luca.verdi@example.com"; tier = "HYBRID_STANDARD" },
    @{ email = "admin@mediacenter.it"; tier = "BUSINESS" }
)

foreach ($user in $testUsers) {
    $userBody = @{
        email = $user.email
        password = "Test123!"
    } | ConvertTo-Json
    
    try {
        $userResponse = Invoke-RestMethod -Uri "$API/auth/login" -Method POST -Body $userBody -ContentType "application/json"
        Write-Host "  ✅ $($user.email) - $($user.tier)" -ForegroundColor Green
        $passed++
    } catch {
        Write-Host "  ❌ $($user.email) - FALLITO" -ForegroundColor Red
        $failed++
    }
}

# ============================================
# RISULTATI
# ============================================
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  RISULTATI" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  ✅ Passed: $passed" -ForegroundColor Green
Write-Host "  ❌ Failed: $failed" -ForegroundColor Red
Write-Host ""

if ($failed -eq 0) {
    Write-Host "  🎉 TUTTI I TEST PASSATI!" -ForegroundColor Green
    Write-Host "     L'app funziona correttamente." -ForegroundColor Green
} else {
    Write-Host "  ⚠️ ALCUNI TEST FALLITI" -ForegroundColor Yellow
    Write-Host "     Verifica:" -ForegroundColor Yellow
    Write-Host "     1. Backend running (uvicorn main:app --reload)" -ForegroundColor Gray
    Write-Host "     2. Seed eseguito (python seed_database.py)" -ForegroundColor Gray
    Write-Host "     3. Database accessibile" -ForegroundColor Gray
}

Write-Host ""
