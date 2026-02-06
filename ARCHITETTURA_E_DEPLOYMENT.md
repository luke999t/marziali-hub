# 🏗️ Architettura e Deployment - Media Center Arti Marziali

**Data creazione**: 20 Novembre 2024
**Ultima modifica**: 20 Novembre 2024

---

## 📊 Requisiti di Scala

- **Utenti target**: Max 200 utenti contemporanei (fase iniziale)
- **Crescita prevista**: Fino a 500 utenti contemporanei entro 12 mesi
- **Tipologia**: Piattaforma di video streaming per arti marziali
- **Zona geografica**: Principalmente Italia/Europa

---

## 🎯 Decisioni Architetturali

### Database: PostgreSQL

**Scelta**: PostgreSQL 15+

**Motivazioni**:
- ✅ Open source, gratuito, robusto
- ✅ Supporto nativo per JSON (metadata video)
- ✅ ARRAY types per tags, categorie
- ✅ Full-text search integrato
- ✅ Ottimo per relazioni complesse (utenti, video, sottoscrizioni)
- ✅ Scalabile fino a milioni di record

**Alternative valutate**:
- ❌ MySQL: meno feature avanzate (no ARRAY, JSON limitato)
- ❌ MongoDB: non ottimale per relazioni complesse
- ❌ SQLite: non adatto per produzione multi-utente

---

## 💻 Ambiente di Sviluppo Locale

### Setup Scelto: PostgreSQL Nativo su Windows

**Motivazioni**:
- ✅ Docker Desktop su Windows ha problemi di pipe communication
- ✅ PostgreSQL nativo è più stabile e performante in locale
- ✅ Stesso motore di produzione (solo modalità diversa)
- ✅ Setup veloce (5 minuti)

**Configurazione e Credenziali**:
```
=== DATABASE ===
Host: localhost
Porta: 5432 (porta standard PostgreSQL)
Database: martial_arts_db

Utente Applicazione:
User: martial_user
Password: martial_pass

Utente Superutente PostgreSQL:
User: postgres
Password: postgres

=== BACKEND JWT ===
SECRET_KEY: dev-secret-key-change-in-production-12345678901234567890
ALGORITHM: HS256
ACCESS_TOKEN_EXPIRE_MINUTES: 30
REFRESH_TOKEN_EXPIRE_DAYS: 7
```

**IMPORTANTE - Credenziali di sviluppo**:
⚠️ Queste password sono SOLO per sviluppo locale
⚠️ NON usare in produzione
⚠️ In produzione generare nuove password sicure

**IMPORTANTE**: Usiamo la porta 5432 (porta standard) perché:
- Un singolo server PostgreSQL può ospitare **multipli database isolati**
- Database "controllo_gestione" (progetto esistente) e "martial_arts_db" (questo progetto) sono completamente separati
- Cambiar la porta in postgresql.conf influenzerebbe TUTTI i database sul server
- Strategia multi-database è più semplice e standard

**File `.env` per sviluppo**:
```env
DATABASE_URL=postgresql://martial_user:martial_pass@localhost:5432/martial_arts_db
DATABASE_URL_ASYNC=postgresql+asyncpg://martial_user:martial_pass@localhost:5432/martial_arts_db
```

**Alternative valutate**:
- ❌ Docker Desktop: problemi di comunicazione pipe su Windows
- ❌ SQLite: tipi incompatibili (no ARRAY), comportamento diverso da produzione
- ✅ PostgreSQL nativo: **SCELTO** - stabile, veloce, identico a produzione

---

## 🚀 Deployment Produzione

### Fase 1: Lancio Iniziale (0-200 utenti)

**Architettura**: VPS singolo con Docker Compose

**Provider consigliato**: Hetzner Cloud CPX21
- **Specs**: 4GB RAM, 3 vCPU, 80GB SSD
- **Costo**: 8.46€/mese
- **Datacenter**: Falkenstein, Germania (EU, GDPR compliant)
- **Link**: https://www.hetzner.com/cloud

**Stack tecnologico**:
```yaml
# docker-compose.yml produzione
services:
  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    # Reverse proxy + SSL termination

  backend:
    build: ./backend
    # FastAPI app
    depends_on:
      - postgres

  frontend:
    build: ./frontend
    # Next.js app

  postgres:
    image: postgres:15
    volumes:
      - postgres_data:/var/lib/postgresql/data
    # Database persistente

  certbot:
    # SSL certificates (Let's Encrypt)
```

**Costi mensili**:
- VPS Hetzner CPX21: 8.46€
- Dominio (.com): ~1€/mese
- **Totale: ~10€/mese**

**Capacità stimata**:
- ✅ 200-500 utenti contemporanei
- ✅ 10.000 richieste/minuto
- ✅ Database fino 50GB
- ✅ Streaming video (con CDN)

---

### Fase 2: Crescita (500-1000 utenti)

**Quando migrare**:
- Database > 50GB
- CPU costantemente > 70%
- Serve ridondanza/alta disponibilità

**Architettura**: Cloud gestito multi-server

**Stack**:
- **Backend**: AWS ECS / Google Cloud Run (auto-scaling)
- **Database**: AWS RDS PostgreSQL / Google Cloud SQL (managed)
- **Frontend**: Vercel / Netlify (CDN globale)
- **Storage video**: AWS S3 / Google Cloud Storage
- **CDN**: CloudFront / Cloudflare

**Costi mensili stimati**:
- Database managed: 50-80€
- Backend containers: 30-50€
- CDN/Storage: 20-30€
- **Totale: 100-160€/mese**

---

### Fase 3: Scala Enterprise (1000+ utenti)

**Quando migrare**:
- > 1000 utenti contemporanei
- Database > 500GB
- Serve multi-region
- Team di sviluppo > 5 persone

**Architettura**: Kubernetes multi-region

**Stack**:
- **Orchestrazione**: Kubernetes (GKE/EKS)
- **Database**: PostgreSQL cluster (Patroni/Stolon)
- **Cache**: Redis cluster
- **Message Queue**: RabbitMQ/Kafka
- **Monitoring**: Prometheus + Grafana
- **Logging**: ELK stack

**Costi mensili stimati**: 500-1000€+

---

## 📦 Containerizzazione

### Sviluppo Locale
- **Docker**: Opzionale (problemi su Windows)
- **Database**: PostgreSQL nativo (porta 5433)

### Produzione
- **Docker**: Obbligatorio
- **Orchestrazione**: Docker Compose (Fase 1) → Kubernetes (Fase 3)

**Immagini Docker**:
```dockerfile
# Backend
FROM python:3.11-slim
# FastAPI + dependencies

# Frontend
FROM node:18-alpine
# Next.js build

# PostgreSQL
FROM postgres:15-alpine
# Database
```

---

## 🔐 Sicurezza e Credenziali

### 📝 Credenziali Sviluppo Locale

**PostgreSQL Database**:
```
Host: localhost:5432
Database: martial_arts_db
User: martial_user
Password: martial_pass

PostgreSQL Superuser:
User: postgres
Password: postgres
```

**Backend API**:
```
JWT Secret: dev-secret-key-change-in-production-12345678901234567890
Algorithm: HS256
Access Token Expiry: 30 minuti
Refresh Token Expiry: 7 giorni
```

**Utenti di Test Creati**:
```
1. mario / mario@test.com / Test1234
2. luca / luca@test.com / Test1234
3. giovanni / giovanni@test.com / Test1234
```

**File `.env` Location**:
```
backend/.env (già configurato)
```

**Connessioni Database**:
```
# Sync (per script)
DATABASE_URL=postgresql://martial_user:martial_pass@localhost:5432/martial_arts_db

# Async (per FastAPI)
DATABASE_URL_ASYNC=postgresql+asyncpg://martial_user:martial_pass@localhost:5432/martial_arts_db
```

### 🔒 Note Sicurezza

**Sviluppo**:
- ⚠️ Password hardcoded in `.env` (NON committato in git)
- ⚠️ `.env` in `.gitignore`
- ⚠️ Credenziali SOLO per sviluppo locale
- ⚠️ NON esporre pubblicamente

**Produzione**:
- 🔒 Secrets gestiti via variabili d'ambiente
- 🔒 SSL/TLS obbligatorio (Let's Encrypt)
- 🔒 Firewall: solo porte 80, 443 esposte
- 🔒 Database non esposto pubblicamente
- 🔒 Password complesse e uniche
- 🔒 Backup automatici giornalieri
- 🔒 Rotazione password ogni 90 giorni

---

## 📈 Piano di Migrazione

### Step 1: Setup Locale (ORA)
1. ✅ Installa PostgreSQL nativo (porta 5433)
2. ✅ Configura `.env` locale
3. ✅ Crea database e tabelle
4. ✅ Testa backend + frontend

### Step 2: Deploy Iniziale (Prossimi mesi)
1. Acquista VPS Hetzner CPX21
2. Installa Docker + Docker Compose
3. Configura dominio + DNS
4. Deploy con `docker-compose up -d`
5. Setup SSL con Certbot
6. Backup automatici

### Step 3: Monitoraggio
1. Setup monitoring (Uptime Kuma / Grafana)
2. Alert su CPU/RAM > 80%
3. Backup test mensili
4. Performance monitoring

### Step 4: Scaling (Quando serve)
1. Upgrade VPS o migrazione cloud gestito
2. Implementa caching (Redis)
3. CDN per video
4. Database replication (se necessario)

---

## 🛠️ Tools e Servizi

### Sviluppo
- **IDE**: VS Code / Claude Code
- **Database GUI**: pgAdmin 4 / DBeaver
- **API Testing**: Postman / Thunder Client
- **Git**: GitHub

### DevOps
- **CI/CD**: GitHub Actions
- **Monitoring**: Uptime Kuma (self-hosted) / UptimeRobot
- **Backup**: Automated PostgreSQL dumps
- **SSL**: Let's Encrypt (Certbot)
- **Domain**: Namecheap / Cloudflare

### Opzionali Futuri
- **Error tracking**: Sentry
- **Analytics**: Plausible / Matomo (self-hosted)
- **Email**: SendGrid / Amazon SES
- **Payment**: Stripe

---

## 💰 Analisi Costi

### Costi Fissi Mensili

**Fase 1 (0-200 utenti)**:
- VPS Hetzner CPX21: 8.46€
- Dominio: 1€
- **Totale: ~10€/mese**

**Fase 2 (500-1000 utenti)**:
- Cloud managed DB: 60€
- Container hosting: 40€
- CDN: 25€
- **Totale: ~125€/mese**

**Fase 3 (1000+ utenti)**:
- Kubernetes cluster: 300€
- Database cluster: 200€
- CDN + Storage: 100€
- **Totale: 600€+/mese**

### ROI Stimato
Con 200 utenti paganti a 10€/mese:
- **Entrate**: 2.000€/mese
- **Costi infra**: 10€/mese
- **Margine**: 99.5% 💰

---

## 📚 Documentazione Tecnica

### Repository
```
media-center-arti-marziali/
├── backend/          # FastAPI
├── frontend/         # Next.js/React
├── mobile/           # Expo React Native
├── docker-compose.yml
├── .env.example
└── docs/
    ├── API.md
    ├── DATABASE.md
    └── DEPLOYMENT.md
```

### Database Schema
- **Modelli principali**: User, Video, Subscription, Maestro, ASD
- **Tipi PostgreSQL usati**: ARRAY, JSON, UUID, TIMESTAMP
- **Indici**: su user.email, video.created_at, subscription.user_id

---

## ✅ Checklist Pre-Deploy

### Prima del deploy in produzione:
- [ ] Backup locale database
- [ ] Test completo funzionalità
- [ ] Security audit (SQL injection, XSS, CSRF)
- [ ] Performance test (100+ utenti simulati)
- [ ] Setup monitoring
- [ ] Documenta procedure rollback
- [ ] DNS configurato
- [ ] SSL certificati pronti
- [ ] Variabili d'ambiente produzione
- [ ] Backup automatici configurati

---

## 🆘 Supporto e Manutenzione

### Backup
- **Frequenza**: Giornaliera (3 AM)
- **Retention**: 30 giorni
- **Storage**: Locale + cloud (Backblaze B2)

### Updates
- **PostgreSQL**: Minor updates mensili, major annuali
- **Docker images**: Rebuild settimanale
- **Dependencies**: Review mensile vulnerabilità

### Incident Response
1. Alert automatico (email/Telegram)
2. Check logs (`docker-compose logs`)
3. Rollback se necessario
4. Post-mortem analysis

---

## 📞 Contatti e Risorse

### Provider
- **Hetzner**: https://www.hetzner.com/cloud
- **Cloudflare**: https://www.cloudflare.com
- **Let's Encrypt**: https://letsencrypt.org

### Community
- **PostgreSQL**: https://www.postgresql.org/support/
- **FastAPI**: https://fastapi.tiangolo.com
- **Docker**: https://docs.docker.com

---

## 🔄 Changelog Decisioni

### 2024-11-20
- ✅ Scelta PostgreSQL come database principale
- ✅ PostgreSQL nativo 15.12 per sviluppo locale
- ✅ Database `martial_arts_db` creato con utente `martial_user`
- ✅ Password superutente PostgreSQL: `postgres`
- ✅ Porta 5432 (standard) - strategia multi-database su stesso server PostgreSQL
- ✅ Coesistenza con progetto "controllo-gestione" tramite database separati
- ✅ VPS Hetzner per deploy iniziale
- ✅ Docker Compose per orchestrazione produzione
- ⏭️ Docker locale rimandato (problemi Windows pipe communication)

---

**Documento living** - aggiornare ad ogni decisione architetturale importante! 📝
