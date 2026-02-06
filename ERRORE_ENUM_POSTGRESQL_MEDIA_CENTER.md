# 🚨 ERRORE ENUM POSTGRESQL - MEDIA CENTER ARTI MARZIALI

**Data:** 2025-01-09  
**Modulo:** Royalties  
**Stato:** PROBLEMA IDENTIFICATO - FIX RICHIESTO

---

## 📋 PROBLEMA

I test royalties falliscono con errore:
```
asyncpg.exceptions.UndefinedObjectError: il tipo "payoutstatus" non esiste
asyncpg.exceptions.UndefinedObjectError: il tipo "royaltymilestone" non esiste
```

## 🔍 ANALISI

### Codice Già Corretto ✅
- **models.py**: Già usa `String(50)` invece di `SQLEnum`
- **service.py**: Già usa `.value` per confronti enum

### Database NON Aggiornato ❌
Le tabelle PostgreSQL sono state create con ENUM types che non esistono più.
Serve ricreare le tabelle o alterare le colonne.

---

## 🛠️ FIX RICHIESTO

### Opzione A: Ricreare Tabelle (Consigliato se database vuoto)
```sql
DROP TABLE IF EXISTS royalty_view_royalties CASCADE;
DROP TABLE IF EXISTS royalty_payouts CASCADE;
DROP TABLE IF EXISTS royalty_blockchain_batches CASCADE;
DROP TABLE IF EXISTS royalty_student_subscriptions CASCADE;
DROP TABLE IF EXISTS royalty_master_profiles CASCADE;
DROP TABLE IF EXISTS royalty_master_switch_history CASCADE;
```

Poi riavviare backend per ricreare con String(50).

### Opzione B: Alter Table (Se dati esistono)
```sql
-- Per ogni tabella con ENUM
ALTER TABLE royalty_view_royalties 
  ALTER COLUMN milestone TYPE VARCHAR(50);

ALTER TABLE royalty_payouts 
  ALTER COLUMN status TYPE VARCHAR(50);

ALTER TABLE royalty_payouts 
  ALTER COLUMN method TYPE VARCHAR(50);

-- etc per tutte le colonne
```

---

## 📊 STATO TEST

| Test | Pre-Fix | Post-Fix Atteso |
|------|---------|-----------------|
| test_track_view_requires_auth | 500 Error | PASS |
| test_get_admin_stats | 500 Error | PASS |
| test_update_config_requires_admin | SKIPPED | SKIPPED |
| Altri 9 test | PASS | PASS |

**Attuale:** 9/12 pass (75%) + 1 skip  
**Atteso dopo fix:** 11/12 pass (92%) + 1 skip

---

## 📝 NOTE IMPORTANTI

1. **STESSO PROBLEMA** di Special Projects (già fixato là)
2. Il fix è solo lato **DATABASE**, il codice è già corretto
3. Se si usa SQLite per test, non c'è questo problema (SQLite ignora ENUM)
4. PostgreSQL richiede DROP/ALTER delle tabelle esistenti

---

## 🎯 AZIONE DA FARE (Claude Code)

```bash
# 1. Connetti a PostgreSQL
psql -U postgres -d media_center

# 2. Esegui DROP delle tabelle royalty
DROP TABLE IF EXISTS royalty_view_royalties CASCADE;
DROP TABLE IF EXISTS royalty_payouts CASCADE;
# ... (tutte le tabelle royalty_*)

# 3. Riavvia backend (ricrea tabelle)
cd C:\Users\utente\Desktop\GESTIONALI\media-center-arti-marziali\backend
python -m uvicorn main:app --port 8000

# 4. Riesegui test
python -m pytest tests/real/test_royalties_real.py -v
```
