# Scripts

## backup_db.py - Database Backup Tool

Script per backup PostgreSQL con compressione gzip e retention policy.

### Requisiti
- PostgreSQL installato (pg_dump, psql nel PATH)
- DATABASE_URL configurato in `.env`

### Comandi

```bash
# Crea backup
python scripts/backup_db.py backup

# Lista backup disponibili
python scripts/backup_db.py list

# Ripristina backup
python scripts/backup_db.py restore --file backup_martial_arts_db_20251121_170258.sql.gz

# Pulizia manuale backup vecchi
python scripts/backup_db.py cleanup
```

### Configurazione (nel file)
- `BACKUP_DIR`: `backend/backups/`
- `RETENTION_DAYS`: 7 giorni
- `MAX_BACKUPS`: 10 backup massimo

### Output
I backup vengono salvati in `backend/backups/` con nome:
```
backup_{db_name}_{YYYYMMDD_HHMMSS}.sql.gz
```

### Note
- I backup sono compressi con gzip
- La cartella `backups/` e' in `.gitignore`
- Per produzione: usare servizio managed (Supabase, Railway) con backup automatici
