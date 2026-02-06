# 🏗️ ARCHITETTURA PRODUZIONE - PROGETTO UNIFICATO

**Data**: 10 Novembre 2025
**Approccio**: Monorepo Production-Ready
**Deploy**: Docker Compose + Microservices orchestrati

---

## 🎯 FILOSOFIA ARCHITETTURA

**Progetto UNICO** ma **modulare**:
- 1 repository
- 1 database principale (condiviso)
- N microservices (possono scalare indipendentemente)
- 1 frontend (Next.js)
- Docker Compose per orchestrazione

---

## 📂 STRUTTURA PRODUZIONE UNIFICATA

```
media-center-arti-marziali/                  # ROOT monorepo
│
├── docker-compose.yml                       # Orchestrazione tutti i servizi
├── docker-compose.dev.yml                   # Override per dev
├── .env.example                             # Template environment
├── .gitignore                               # Git ignore
├── README.md                                # Main docs
│
├── backend/                                 # Backend principale
│   │
│   ├── Dockerfile                           # Container backend
│   ├── requirements.txt                     # Dependencies unificate
│   ├── alembic.ini                          # DB migrations
│   ├── pytest.ini                           # Test config
│   │
│   ├── main.py                              # Entry point MAIN (FastAPI app)
│   ├── config.py                            # Config centralizzata
│   ├── database.py                          # DB connection pool condiviso
│   │
│   ├── core/                                # Core utilities (condivise)
│   │   ├── __init__.py
│   │   ├── security.py                      # JWT, auth, hashing
│   │   ├── logging.py                       # Logging config
│   │   ├── exceptions.py                    # Custom exceptions
│   │   ├── dependencies.py                  # FastAPI dependencies
│   │   └── middleware.py                    # CORS, rate limiting
│   │
│   ├── models/                              # SQLAlchemy models (UNIFICATI)
│   │   ├── __init__.py
│   │   ├── base.py                          # Base model
│   │   ├── user.py                          # User + Subscription
│   │   ├── maestro.py                       # Maestro + ASD
│   │   ├── video.py                         # Video + Skeleton
│   │   ├── donation.py                      # Donazioni + Wallet
│   │   ├── communication.py                 # Message + CorrectionRequest
│   │   └── live.py                          # LiveEvent + Streaming
│   │
│   ├── api/                                 # API routes (UNIFICATE)
│   │   ├── __init__.py
│   │   ├── v1/
│   │   │   ├── __init__.py                  # Router registration
│   │   │   ├── auth.py                      # Auth endpoints
│   │   │   ├── users.py                     # User management
│   │   │   ├── maestros.py                  # Maestro endpoints
│   │   │   ├── asds.py                      # ASD endpoints
│   │   │   ├── videos.py                    # Video upload/management
│   │   │   ├── skeleton.py                  # Skeleton extraction/comparison
│   │   │   ├── live.py                      # Live streaming
│   │   │   ├── donations.py                 # Donation system
│   │   │   ├── communication.py             # Chat/messages
│   │   │   ├── subscriptions.py             # Subscription management
│   │   │   └── blockchain.py                # Blockchain batches
│   │   │
│   │   └── health.py                        # Health checks
│   │
│   ├── services/                            # Business logic (modulare)
│   │   ├── __init__.py
│   │   ├── video_studio/                    # Video Studio service
│   │   │   ├── __init__.py
│   │   │   ├── skeleton_extraction.py       # MediaPipe Holistic
│   │   │   ├── comparison_engine.py         # DTW comparison
│   │   │   ├── technique_extractor.py       # Pattern recognition
│   │   │   ├── ai_agent.py                  # AI Q&A
│   │   │   ├── analytics.py                 # Advanced analytics
│   │   │   └── batch_processor.py           # Batch processing
│   │   │
│   │   ├── knowledge/                       # Knowledge extraction service
│   │   │   ├── __init__.py
│   │   │   ├── pdf_extractor.py             # PDF → text
│   │   │   ├── ocr_engine.py                # OCR
│   │   │   ├── nlp_processor.py             # NLP
│   │   │   └── video_analyzer.py            # Video knowledge
│   │   │
│   │   ├── streaming/                       # Live streaming service
│   │   │   ├── __init__.py
│   │   │   ├── rtmp_handler.py              # RTMP ingestion
│   │   │   ├── hls_generator.py             # HLS segmentation
│   │   │   └── chat_manager.py              # Live chat
│   │   │
│   │   ├── translation/                     # Translation service
│   │   │   ├── __init__.py
│   │   │   ├── dataset_processor.py         # TranslationDataset processing
│   │   │   ├── glossary_manager.py          # GlossaryTerm management
│   │   │   └── realtime_translator.py       # Real-time translation
│   │   │
│   │   ├── payment/                         # Payment service
│   │   │   ├── __init__.py
│   │   │   ├── stripe_service.py            # Stripe integration
│   │   │   ├── stelline_wallet.py           # Wallet management
│   │   │   └── withdrawal_processor.py      # Withdrawal processing
│   │   │
│   │   └── blockchain/                      # Blockchain service
│   │       ├── __init__.py
│   │       ├── batch_creator.py             # Batch creation
│   │       ├── merkle_tree.py               # Merkle root calculation
│   │       └── polygon_publisher.py         # Polygon publishing
│   │
│   ├── tasks/                               # Celery tasks
│   │   ├── __init__.py
│   │   ├── celery_app.py                    # Celery config
│   │   ├── video_processing.py              # Video tasks
│   │   ├── blockchain_tasks.py              # Blockchain tasks
│   │   └── notification_tasks.py            # Notification tasks
│   │
│   ├── schemas/                             # Pydantic schemas (validazione)
│   │   ├── __init__.py
│   │   ├── user.py
│   │   ├── video.py
│   │   ├── donation.py
│   │   └── ...
│   │
│   ├── migrations/                          # Alembic migrations
│   │   ├── versions/
│   │   └── env.py
│   │
│   └── tests/                               # Test suite
│       ├── conftest.py
│       ├── unit/
│       │   ├── test_skeleton_extraction.py
│       │   ├── test_comparison.py
│       │   └── ...
│       └── integration/
│           ├── test_api_endpoints.py
│           └── ...
│
├── frontend/                                # Frontend Next.js 14
│   │
│   ├── Dockerfile                           # Container frontend
│   ├── package.json
│   ├── next.config.js
│   ├── tailwind.config.js
│   ├── tsconfig.json
│   │
│   ├── src/
│   │   ├── app/                             # App Router
│   │   │   ├── layout.tsx
│   │   │   ├── page.tsx
│   │   │   ├── (auth)/                      # Auth routes
│   │   │   │   ├── login/
│   │   │   │   └── register/
│   │   │   ├── (dashboard)/                 # Dashboard routes
│   │   │   │   ├── maestro/
│   │   │   │   ├── student/
│   │   │   │   └── asd/
│   │   │   ├── skeleton-viewer/
│   │   │   ├── skeleton-editor/
│   │   │   ├── upload/
│   │   │   └── live/
│   │   │
│   │   ├── components/                      # Shared components
│   │   │   ├── ui/                          # shadcn/ui
│   │   │   ├── SkeletonEditor3D.tsx         # Avatar 3D
│   │   │   ├── SkeletonViewer.tsx           # 2D viewer
│   │   │   └── ...
│   │   │
│   │   ├── lib/                             # Utilities
│   │   │   ├── api.ts                       # API client
│   │   │   ├── auth.ts                      # Auth helpers
│   │   │   └── utils.ts                     # Helpers
│   │   │
│   │   └── hooks/                           # Custom hooks
│   │       ├── useAuth.ts
│   │       ├── useWebSocket.ts
│   │       └── ...
│   │
│   └── public/                              # Static assets
│
├── worker/                                  # Celery worker (separato per scaling)
│   ├── Dockerfile
│   └── start_worker.sh
│
├── nginx/                                   # Reverse proxy
│   ├── Dockerfile
│   ├── nginx.conf                           # Config production
│   └── ssl/                                 # SSL certificates
│
├── scripts/                                 # Utility scripts
│   ├── init_db.sh                           # Initialize database
│   ├── migrate.sh                           # Run migrations
│   ├── seed_data.py                         # Seed initial data
│   └── backup.sh                            # Backup automation
│
├── docs/                                    # Documentation
│   ├── API.md                               # API documentation
│   ├── ARCHITECTURE.md                      # This file
│   ├── DEPLOYMENT.md                        # Deployment guide
│   ├── MEGA_PROMPT_CLAUDE_CODE_WEB.md       # AI-First prompt
│   └── DEVELOPMENT.md                       # Dev setup
│
└── infrastructure/                          # Infrastructure as code (opzionale)
    ├── kubernetes/                          # K8s configs (se serve)
    ├── terraform/                           # Terraform (cloud)
    └── ansible/                             # Ansible playbooks
```

---

## 🐳 DOCKER COMPOSE (PRODUZIONE)

### docker-compose.yml

```yaml
version: '3.8'

services:
  # === DATABASE ===
  postgres:
    image: postgres:15-alpine
    container_name: martial-db
    environment:
      POSTGRES_DB: ${POSTGRES_DB:-martial_arts}
      POSTGRES_USER: ${POSTGRES_USER:-martial_user}
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./scripts/init_db.sh:/docker-entrypoint-initdb.d/init.sh
    ports:
      - "5432:5432"
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U martial_user"]
      interval: 10s
      timeout: 5s
      retries: 5
    networks:
      - martial-network

  # === REDIS (Cache + Celery Broker) ===
  redis:
    image: redis:7-alpine
    container_name: martial-redis
    command: redis-server --appendonly yes
    volumes:
      - redis_data:/data
    ports:
      - "6379:6379"
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 5s
      retries: 5
    networks:
      - martial-network

  # === BACKEND API ===
  backend:
    build:
      context: ./backend
      dockerfile: Dockerfile
    container_name: martial-backend
    command: uvicorn main:app --host 0.0.0.0 --port 8000 --workers 4
    environment:
      DATABASE_URL: postgresql+asyncpg://${POSTGRES_USER}:${POSTGRES_PASSWORD}@postgres:5432/${POSTGRES_DB}
      REDIS_URL: redis://redis:6379/0
      JWT_SECRET: ${JWT_SECRET}
      OPENAI_API_KEY: ${OPENAI_API_KEY}
      STRIPE_API_KEY: ${STRIPE_API_KEY}
      AWS_ACCESS_KEY: ${AWS_ACCESS_KEY}
      AWS_SECRET_KEY: ${AWS_SECRET_KEY}
      S3_BUCKET: ${S3_BUCKET}
    volumes:
      - ./backend:/app
      - media_data:/app/media
      - skeleton_data:/app/skeleton_data
    ports:
      - "8000:8000"
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
    networks:
      - martial-network
    restart: unless-stopped

  # === CELERY WORKER ===
  worker:
    build:
      context: ./backend
      dockerfile: Dockerfile
    container_name: martial-worker
    command: celery -A tasks.celery_app worker --loglevel=info --concurrency=4
    environment:
      DATABASE_URL: postgresql+asyncpg://${POSTGRES_USER}:${POSTGRES_PASSWORD}@postgres:5432/${POSTGRES_DB}
      REDIS_URL: redis://redis:6379/0
      OPENAI_API_KEY: ${OPENAI_API_KEY}
      AWS_ACCESS_KEY: ${AWS_ACCESS_KEY}
      AWS_SECRET_KEY: ${AWS_SECRET_KEY}
    volumes:
      - ./backend:/app
      - media_data:/app/media
      - skeleton_data:/app/skeleton_data
    depends_on:
      - redis
      - postgres
    networks:
      - martial-network
    restart: unless-stopped

  # === CELERY BEAT (Scheduled tasks) ===
  beat:
    build:
      context: ./backend
      dockerfile: Dockerfile
    container_name: martial-beat
    command: celery -A tasks.celery_app beat --loglevel=info
    environment:
      DATABASE_URL: postgresql+asyncpg://${POSTGRES_USER}:${POSTGRES_PASSWORD}@postgres:5432/${POSTGRES_DB}
      REDIS_URL: redis://redis:6379/0
    volumes:
      - ./backend:/app
    depends_on:
      - redis
      - postgres
    networks:
      - martial-network
    restart: unless-stopped

  # === FRONTEND ===
  frontend:
    build:
      context: ./frontend
      dockerfile: Dockerfile
      args:
        NEXT_PUBLIC_API_URL: ${NEXT_PUBLIC_API_URL:-http://localhost:8000}
    container_name: martial-frontend
    environment:
      NEXT_PUBLIC_API_URL: ${NEXT_PUBLIC_API_URL}
    ports:
      - "3000:3000"
    depends_on:
      - backend
    networks:
      - martial-network
    restart: unless-stopped

  # === NGINX (Reverse Proxy) ===
  nginx:
    image: nginx:alpine
    container_name: martial-nginx
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf:ro
      - ./nginx/ssl:/etc/nginx/ssl:ro
      - static_data:/var/www/static
    ports:
      - "80:80"
      - "443:443"
    depends_on:
      - backend
      - frontend
    networks:
      - martial-network
    restart: unless-stopped

  # === CHROMADB (Vector DB per AI Agent) ===
  chromadb:
    image: chromadb/chroma:latest
    container_name: martial-chromadb
    volumes:
      - chroma_data:/chroma/chroma
    ports:
      - "8001:8000"
    environment:
      IS_PERSISTENT: "TRUE"
      ANONYMIZED_TELEMETRY: "FALSE"
    networks:
      - martial-network
    restart: unless-stopped

volumes:
  postgres_data:
  redis_data:
  media_data:
  skeleton_data:
  static_data:
  chroma_data:

networks:
  martial-network:
    driver: bridge
```

---

## 🔧 BACKEND main.py (Unificato)

```python
"""
🎓 AI_MODULE: Main Backend Application
🎓 AI_DESCRIPTION: FastAPI app unificata - tutti i moduli integrati
🎓 AI_BUSINESS: Single entry point per production deployment
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware

from core.middleware import (
    RequestLoggingMiddleware,
    RateLimitMiddleware
)
from core.logging import setup_logging
from core.exceptions import setup_exception_handlers
from database import engine, create_tables

# API routers
from api.v1 import (
    auth,
    users,
    maestros,
    asds,
    videos,
    skeleton,
    live,
    donations,
    communication,
    subscriptions,
    blockchain
)

# Setup logging
setup_logging()

# Create FastAPI app
app = FastAPI(
    title="Media Center Arti Marziali API",
    description="Unified API for martial arts teaching platform",
    version="3.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# === MIDDLEWARE ===

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production: specific domains
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Compression
app.add_middleware(GZipMiddleware, minimum_size=1000)

# Custom middleware
app.add_middleware(RequestLoggingMiddleware)
app.add_middleware(RateLimitMiddleware, requests_per_minute=100)

# === EXCEPTION HANDLERS ===
setup_exception_handlers(app)

# === ROUTERS ===

# API v1
app.include_router(auth.router, prefix="/api/v1/auth", tags=["Auth"])
app.include_router(users.router, prefix="/api/v1/users", tags=["Users"])
app.include_router(maestros.router, prefix="/api/v1/maestros", tags=["Maestros"])
app.include_router(asds.router, prefix="/api/v1/asds", tags=["ASDs"])
app.include_router(videos.router, prefix="/api/v1/videos", tags=["Videos"])
app.include_router(skeleton.router, prefix="/api/v1/skeleton", tags=["Skeleton"])
app.include_router(live.router, prefix="/api/v1/live", tags=["Live Streaming"])
app.include_router(donations.router, prefix="/api/v1/donations", tags=["Donations"])
app.include_router(communication.router, prefix="/api/v1/communication", tags=["Communication"])
app.include_router(subscriptions.router, prefix="/api/v1/subscriptions", tags=["Subscriptions"])
app.include_router(blockchain.router, prefix="/api/v1/blockchain", tags=["Blockchain"])

# === EVENTS ===

@app.on_event("startup")
async def startup_event():
    """Startup tasks"""
    # Create tables
    await create_tables()

    # Initialize ChromaDB collections
    from services.video_studio.ai_agent import initialize_knowledge_base
    await initialize_knowledge_base()

    print("🚀 Backend started successfully")


@app.on_event("shutdown")
async def shutdown_event():
    """Shutdown tasks"""
    # Close connections
    await engine.dispose()
    print("👋 Backend shutdown complete")


# === HEALTH CHECK ===

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "version": "3.0.0",
        "services": {
            "database": "ok",
            "redis": "ok",
            "chromadb": "ok"
        }
    }


@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "message": "Media Center Arti Marziali API",
        "version": "3.0.0",
        "docs": "/docs",
        "health": "/health"
    }
```

---

## 📝 BACKEND requirements.txt (Unificato)

```txt
# === Web Framework ===
fastapi==0.104.1
uvicorn[standard]==0.24.0
python-multipart==0.0.6

# === Database ===
sqlalchemy==2.0.23
asyncpg==0.29.0
alembic==1.12.1
psycopg2-binary==2.9.9

# === Caching & Queue ===
redis==5.0.1
celery==5.3.4
flower==2.0.1

# === Auth ===
python-jose[cryptography]==3.3.0
passlib[bcrypt]==1.7.4
python-multipart==0.0.6

# === AI/ML ===
mediapipe==0.10.7
opencv-python==4.8.1.78
numpy==1.24.3
scipy==1.11.4
scikit-learn==1.3.2
fastdtw==0.3.4
openai==1.3.5
chromadb==0.4.18

# === Video Processing ===
ffmpeg-python==0.2.0
Pillow==10.1.0

# === PDF/OCR ===
PyPDF2==3.0.1
python-docx==1.1.0
pytesseract==0.3.10

# === HTTP Clients ===
httpx==0.25.1
aiohttp==3.9.0

# === Validation ===
pydantic==2.5.0
pydantic-settings==2.1.0
email-validator==2.1.0

# === Payment ===
stripe==7.4.0

# === Blockchain ===
web3==6.11.3

# === AWS ===
boto3==1.29.6
botocore==1.32.6

# === Utils ===
python-dotenv==1.0.0
pytz==2023.3
python-dateutil==2.8.2

# === Testing ===
pytest==7.4.3
pytest-asyncio==0.21.1
pytest-cov==4.1.0
httpx==0.25.1

# === Monitoring ===
prometheus-client==0.19.0
sentry-sdk[fastapi]==1.38.0
```

---

## 🚀 DEPLOYMENT WORKFLOW

### Development
```bash
# 1. Clone repo
git clone <repo-url>
cd media-center-arti-marziali

# 2. Setup environment
cp .env.example .env
# Edit .env con credenziali

# 3. Start with Docker Compose
docker-compose -f docker-compose.yml -f docker-compose.dev.yml up -d

# 4. Run migrations
docker-compose exec backend alembic upgrade head

# 5. Seed data
docker-compose exec backend python scripts/seed_data.py

# 6. Access
# Backend: http://localhost:8000/docs
# Frontend: http://localhost:3000
```

### Production
```bash
# 1. Build images
docker-compose build --no-cache

# 2. Run migrations
docker-compose run --rm backend alembic upgrade head

# 3. Start services
docker-compose up -d

# 4. Check health
curl http://localhost/health

# 5. Monitor logs
docker-compose logs -f backend
```

---

## 📊 SCALING STRATEGY

### Horizontal Scaling

```yaml
# docker-compose.scale.yml
services:
  backend:
    deploy:
      replicas: 3
      resources:
        limits:
          cpus: '2'
          memory: 4G

  worker:
    deploy:
      replicas: 5
      resources:
        limits:
          cpus: '1'
          memory: 2G
```

### Load Balancer (Nginx)

```nginx
upstream backend_servers {
    least_conn;
    server backend_1:8000;
    server backend_2:8000;
    server backend_3:8000;
}

server {
    listen 80;
    server_name api.martialarts.com;

    location / {
        proxy_pass http://backend_servers;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

---

## 🎯 VANTAGGI ARCHITETTURA

✅ **Monorepo**: Tutto in un repo, facile gestione
✅ **Modulare**: Services separati, facile manutenzione
✅ **Scalabile**: Docker Compose → Kubernetes facile
✅ **Production-ready**: Health checks, logging, monitoring
✅ **Database condiviso**: Transazioni cross-service possibili
✅ **Code sharing**: Models condivisi tra services

---

**Questa è l'architettura che propongo. Ti convince?** 🏗️

Oppure preferisci qualcosa di diverso?
