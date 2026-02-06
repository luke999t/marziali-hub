# Deployment Guide - Media Center Arti Marziali

**Data**: 2025-01-28
**Versione**: 1.0.0

---

## Architettura Deployment

```
                    ┌─────────────┐
                    │  GitHub      │
                    │  Actions CI  │
                    └──────┬──────┘
                           │
              ┌────────────┼────────────┐
              │            │            │
        ┌─────▼─────┐ ┌───▼───┐ ┌─────▼─────┐
        │  Backend   │ │Frontend│ │  Flutter   │
        │  Docker    │ │ Docker │ │  APK/AAB   │
        └─────┬─────┘ └───┬───┘ └─────┬─────┘
              │            │            │
        ┌─────▼─────┐ ┌───▼───┐ ┌─────▼─────┐
        │   GHCR    │ │ GHCR  │ │  GitHub    │
        │  Registry │ │Registry│ │  Releases  │
        └─────┬─────┘ └───┬───┘ └───────────┘
              │            │
        ┌─────▼────────────▼─────┐
        │       VPS Server       │
        │   docker-compose up    │
        └────────────────────────┘
```

---

## Prerequisiti

### Server (VPS)
- Ubuntu 22.04+ / Debian 12+
- Docker 24.0+
- Docker Compose v2
- 4GB RAM minimo (8GB raccomandato)
- 50GB disco
- Dominio configurato con DNS

### GitHub Repository
- Repository con accesso ai GitHub Actions
- Secrets configurati (vedi sezione sotto)

### Sviluppatore
- Docker Desktop (per build locali)
- Flutter SDK 3.19.0+ (per build mobile)
- Python 3.11+ (per backend locale)
- Node.js 20+ (per frontend locale)

---

## Environment Variables

### Backend (.env)
```env
# Database
DATABASE_URL=postgresql://user:password@db:5432/media_center
DATABASE_URL_ASYNC=postgresql+asyncpg://user:password@db:5432/media_center

# Redis
REDIS_URL=redis://redis:6379

# Security
SECRET_KEY=<generare-con-openssl-rand-hex-32>
JWT_ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30

# Email
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USER=noreply@example.com
SMTP_PASSWORD=<password>

# Stripe
STRIPE_SECRET_KEY=sk_live_...
STRIPE_WEBHOOK_SECRET=whsec_...

# Sentry
SENTRY_DSN=https://...@sentry.io/...

# Monitoring
ENABLE_METRICS=true

# Environment
ENVIRONMENT=production
DEBUG=false
```

### Frontend (.env.production)
```env
NEXT_PUBLIC_API_URL=https://api.example.com
NEXT_PUBLIC_WS_URL=wss://api.example.com
NEXT_PUBLIC_SENTRY_DSN=https://...@sentry.io/...
```

### GitHub Secrets (richiesti)
| Secret | Descrizione |
|--------|-------------|
| `VPS_HOST` | IP o dominio del server |
| `VPS_USER` | Username SSH |
| `VPS_SSH_KEY` | Chiave SSH privata |
| `API_URL` | URL del backend API |
| `KEYSTORE_BASE64` | Keystore Android (base64, per Flutter) |

---

## Deployment Step-by-Step

### 1. Setup Iniziale Server

```bash
# Connetti al server
ssh user@your-server

# Installa Docker
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER

# Crea directory
sudo mkdir -p /opt/media-center
sudo chown $USER:$USER /opt/media-center
cd /opt/media-center

# Clona repo (o copia files)
git clone https://github.com/your-org/media-center-arti-marziali.git .

# Crea .env
cp .env.example .env
nano .env  # Configura variabili
```

### 2. Primo Deploy (Manuale)

```bash
cd /opt/media-center

# Build e avvia tutti i servizi
docker compose -f docker-compose.prod.yml up -d

# Verifica status
docker compose -f docker-compose.prod.yml ps

# Verifica health
curl http://localhost:8000/health

# Inizializza database
docker compose -f docker-compose.prod.yml exec backend \
  python -c "from main import app; print('OK')"

# Seed dati iniziali (opzionale)
docker compose -f docker-compose.prod.yml exec backend \
  python seed_database.py
```

### 3. Deploy Automatico (CI/CD)

Il deploy automatico avviene tramite GitHub Actions su push al branch `main`:

1. **CI Pipeline** verifica tutti i test
2. **Deploy Pipeline** builda e pusha le immagini Docker
3. **SSH Deploy** aggiorna i container sul server
4. **Health Check** verifica il deploy

```bash
# Trigger manuale (dalla UI di GitHub Actions o CLI)
gh workflow run deploy.yml -f component=all -f environment=production
```

### 4. Deploy Flutter App

```bash
# Build APK locale
cd flutter_app
flutter build apk --release

# Build AAB per Play Store
flutter build appbundle --release

# Deploy via GitHub Actions (tag)
git tag -a v1.0.0 -m "Release 1.0.0"
git push origin v1.0.0
```

---

## Rollback Procedures

### Backend Rollback

```bash
# Opzione 1: Rollback all'immagine precedente
ssh user@server
cd /opt/media-center
docker compose -f docker-compose.prod.yml pull backend
docker compose -f docker-compose.prod.yml up -d backend

# Opzione 2: Rollback a versione specifica
docker pull ghcr.io/org/media-center/backend:2025.01.27-abc1234
docker tag ghcr.io/org/media-center/backend:2025.01.27-abc1234 \
           ghcr.io/org/media-center/backend:latest
docker compose -f docker-compose.prod.yml up -d backend

# Opzione 3: Rollback da git
git revert HEAD
git push origin main
# Il CI/CD eseguira' il deploy automatico
```

### Frontend Rollback

```bash
# Stesso approccio del backend
docker pull ghcr.io/org/media-center/frontend:<previous-tag>
docker tag ghcr.io/org/media-center/frontend:<previous-tag> \
           ghcr.io/org/media-center/frontend:latest
docker compose -f docker-compose.prod.yml up -d frontend
```

### Database Rollback

```bash
# Backup prima del deploy (automatico nel CI)
docker compose exec db pg_dump -U postgres media_center > backup_$(date +%Y%m%d).sql

# Restore
docker compose exec -T db psql -U postgres media_center < backup_20250128.sql
```

---

## Monitoring

### Stack Monitoring
```bash
# Avvia stack monitoring
docker compose -f docker-compose.monitoring.yml up -d

# Accessi:
# Grafana:     http://server:3000 (admin/admin)
# Prometheus:  http://server:9090
# Alertmanager: http://server:9093
```

### Health Check Endpoints
| Endpoint | Descrizione |
|----------|-------------|
| `GET /health` | Backend health check |
| `GET /metrics` | Prometheus metrics |
| `GET :3000` | Grafana dashboard |
| `GET :9090` | Prometheus UI |

### Log Monitoring
```bash
# Tutti i log
docker compose -f docker-compose.prod.yml logs -f

# Solo backend
docker compose -f docker-compose.prod.yml logs -f backend

# Ultimi 100 log
docker compose -f docker-compose.prod.yml logs --tail=100 backend
```

---

## Load Testing

```bash
# Installa Locust
pip install locust

# Test con UI
cd load_tests
locust -f locustfile.py --host=https://api.example.com

# Test headless (1000 utenti target)
locust -f locustfile.py --host=https://api.example.com \
  --headless -u 1000 -r 100 -t 15m \
  --html=reports/production_test.html
```

---

## Troubleshooting

### Container non si avvia
```bash
# Controlla i log
docker compose -f docker-compose.prod.yml logs backend

# Controlla risorse
docker stats
df -h
free -m

# Riavvia servizio
docker compose -f docker-compose.prod.yml restart backend
```

### Database connection error
```bash
# Verifica che PostgreSQL sia attivo
docker compose -f docker-compose.prod.yml exec db pg_isready

# Verifica connessione
docker compose -f docker-compose.prod.yml exec backend \
  python -c "from core.database import engine; print('DB OK')"
```

### Out of memory
```bash
# Controlla uso memoria
docker stats --no-stream

# Aumenta limiti in docker-compose.prod.yml
# deploy:
#   resources:
#     limits:
#       memory: 2G
```

### SSL/HTTPS
```bash
# Setup con Certbot (Let's Encrypt)
sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d api.example.com -d www.example.com

# Rinnovo automatico
sudo certbot renew --dry-run
```

---

## Checklist Pre-Deploy

- [ ] Tutti i test passano in CI
- [ ] Environment variables configurate
- [ ] Database backup eseguito
- [ ] SSL certificato valido
- [ ] DNS configurato
- [ ] Monitoring attivo
- [ ] Rollback plan verificato
- [ ] Team notificato

---

*Documento generato: 2025-01-28*
