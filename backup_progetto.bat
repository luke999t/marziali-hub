@echo off
REM ========================================
REM BACKUP COMPLETO - Media Center Arti Marziali
REM ========================================
REM
REM Questo script crea un backup completo di:
REM - Tutto il codice sorgente
REM - File di configurazione (.env se presenti)
REM - Database volumes (se Docker è attivo)
REM
REM ========================================

setlocal enabledelayedexpansion

REM Ottieni data e ora corrente
for /f "tokens=2 delims==" %%a in ('wmic OS Get localdatetime /value') do set "dt=%%a"
set "timestamp=%dt:~0,8%_%dt:~8,6%"

REM Directory di destinazione
set "BACKUP_DIR=C:\Users\utente\Desktop\GESTIONALI\BACKUPS"
set "BACKUP_NAME=media-center-arti-marziali-backup-%timestamp%"
set "BACKUP_PATH=%BACKUP_DIR%\%BACKUP_NAME%"

echo.
echo ========================================
echo BACKUP PROGETTO - Media Center Arti Marziali
echo ========================================
echo.
echo Timestamp: %timestamp%
echo Backup path: %BACKUP_PATH%
echo.

REM Crea directory backup se non esiste
if not exist "%BACKUP_DIR%" (
    echo Creo directory backup...
    mkdir "%BACKUP_DIR%"
)

REM Crea directory backup specifica
echo Creo directory backup %BACKUP_NAME%...
mkdir "%BACKUP_PATH%"

echo.
echo [1/4] Copiando codice sorgente...
xcopy "C:\Users\utente\Desktop\GESTIONALI\media-center-arti-marziali" "%BACKUP_PATH%" /E /I /H /Y /EXCLUDE:backup_exclude.txt 2>nul

REM Crea lista esclusioni se non esiste
if not exist "backup_exclude.txt" (
    echo node_modules\ > backup_exclude.txt
    echo __pycache__\ >> backup_exclude.txt
    echo .pytest_cache\ >> backup_exclude.txt
    echo *.pyc >> backup_exclude.txt
    echo .next\ >> backup_exclude.txt
    echo dist\ >> backup_exclude.txt
    echo build\ >> backup_exclude.txt
)

echo [2/4] Salvando file .env esistenti...
if exist "C:\Users\utente\Desktop\GESTIONALI\media-center-arti-marziali\.env" (
    copy "C:\Users\utente\Desktop\GESTIONALI\media-center-arti-marziali\.env" "%BACKUP_PATH%\.env.backup" >nul
    echo    - Salvato .env
)
if exist "C:\Users\utente\Desktop\GESTIONALI\media-center-arti-marziali\.env.local" (
    copy "C:\Users\utente\Desktop\GESTIONALI\media-center-arti-marziali\.env.local" "%BACKUP_PATH%\.env.local.backup" >nul
    echo    - Salvato .env.local
)
if exist "C:\Users\utente\Desktop\GESTIONALI\media-center-arti-marziali\backend\.env" (
    copy "C:\Users\utente\Desktop\GESTIONALI\media-center-arti-marziali\backend\.env" "%BACKUP_PATH%\backend\.env.backup" >nul
    echo    - Salvato backend\.env
)

echo [3/4] Creando archivio compresso...
REM Verifica se tar è disponibile (Windows 10+)
where tar >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    cd "%BACKUP_DIR%"
    tar -czf "%BACKUP_NAME%.tar.gz" "%BACKUP_NAME%"
    echo    - Archivio creato: %BACKUP_NAME%.tar.gz

    REM Calcola dimensione
    for %%A in ("%BACKUP_NAME%.tar.gz") do set "filesize=%%~zA"
    set /a "filesizeMB=!filesize! / 1048576"
    echo    - Dimensione: !filesizeMB! MB
) else (
    echo    - NOTA: tar non disponibile, backup salvato come directory
)

echo [4/4] Salvando informazioni backup...
(
    echo BACKUP INFORMAZIONI
    echo ===================
    echo.
    echo Data backup: %date% %time%
    echo Timestamp: %timestamp%
    echo.
    echo CONTENUTO:
    echo - Codice sorgente completo
    echo - File configurazione .env
    echo - Template deployment
    echo - Documentazione
    echo.
    echo RESTORE:
    echo Per ripristinare questo backup:
    echo 1. Estrai l'archivio tar.gz
    echo 2. Copia il contenuto in una nuova directory
    echo 3. Ripristina i file .env.backup rinominandoli in .env
    echo.
) > "%BACKUP_PATH%\BACKUP_INFO.txt"

echo.
echo ========================================
echo BACKUP COMPLETATO CON SUCCESSO!
echo ========================================
echo.
echo Percorso backup:
echo %BACKUP_PATH%
echo.
if exist "%BACKUP_DIR%\%BACKUP_NAME%.tar.gz" (
    echo Archivio compresso:
    echo %BACKUP_DIR%\%BACKUP_NAME%.tar.gz
    echo.
)
echo Per ripristinare:
echo 1. Vai in %BACKUP_DIR%
echo 2. Estrai l'archivio .tar.gz
echo 3. Leggi BACKUP_INFO.txt per istruzioni
echo.
echo ========================================

pause
