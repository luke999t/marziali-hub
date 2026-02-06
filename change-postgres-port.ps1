# Script per cambiare porta PostgreSQL da 5432 a 5433
# Eseguire come Amministratore

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Cambio porta PostgreSQL: 5432 -> 5433" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Path del file di configurazione
$configFile = "C:\Program Files\PostgreSQL\15\data\postgresql.conf"

# Verifica che il file esista
if (-Not (Test-Path $configFile)) {
    Write-Host "ERRORE: File di configurazione non trovato!" -ForegroundColor Red
    Write-Host "Path cercato: $configFile" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Premi un tasto per uscire..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    exit 1
}

Write-Host "File di configurazione trovato: OK" -ForegroundColor Green
Write-Host ""

# Backup del file originale
$backupFile = "$configFile.backup_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
Copy-Item $configFile $backupFile
Write-Host "Backup creato: $backupFile" -ForegroundColor Green
Write-Host ""

# Leggi il contenuto
$content = Get-Content $configFile

# Trova e sostituisci la porta
$newContent = $content -replace "^#?port\s*=\s*5432", "port = 5433"

# Salva il nuovo contenuto
Set-Content -Path $configFile -Value $newContent

Write-Host "Porta cambiata a 5433 nel file di configurazione" -ForegroundColor Green
Write-Host ""

# Riavvia il servizio PostgreSQL
Write-Host "Riavvio del servizio PostgreSQL..." -ForegroundColor Yellow

try {
    Restart-Service -Name "postgresql-x64-15" -ErrorAction Stop
    Write-Host "Servizio PostgreSQL riavviato con successo!" -ForegroundColor Green
    Write-Host ""
} catch {
    Write-Host "ATTENZIONE: Non è stato possibile riavviare automaticamente il servizio." -ForegroundColor Yellow
    Write-Host "Riavvialo manualmente:" -ForegroundColor Yellow
    Write-Host "1. Premi Win+R" -ForegroundColor White
    Write-Host "2. Digita: services.msc" -ForegroundColor White
    Write-Host "3. Trova 'postgresql-x64-15'" -ForegroundColor White
    Write-Host "4. Tasto destro -> Riavvia" -ForegroundColor White
    Write-Host ""
}

# Verifica la connessione sulla nuova porta
Write-Host "Verifica connessione sulla porta 5433..." -ForegroundColor Yellow
Start-Sleep -Seconds 3

try {
    $result = & psql -U postgres -p 5433 -l 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "SUCCESS! PostgreSQL risponde sulla porta 5433" -ForegroundColor Green
    } else {
        Write-Host "Il servizio potrebbe non essere ancora pronto. Riprova tra qualche secondo:" -ForegroundColor Yellow
        Write-Host "psql -U postgres -p 5433 -l" -ForegroundColor White
    }
} catch {
    Write-Host "Verifica manuale con: psql -U postgres -p 5433 -l" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Operazione completata!" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Prossimi passi:" -ForegroundColor White
Write-Host "1. Aggiorna .env del progetto con porta 5433" -ForegroundColor White
Write-Host "2. Riavvia il backend" -ForegroundColor White
Write-Host ""
Write-Host "Premi un tasto per uscire..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
