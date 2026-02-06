# 🚀 DEPLOYMENT GUIDE - Media Center Arti Marziali
**Production Deployment Step-by-Step**

---

## 📋 PRE-REQUISITI

### 1. Server Requirements
- **OS:** Ubuntu 22.04 LTS (o compatibile)
- **CPU:** 4+ cores
- **RAM:** 8GB+ (16GB raccomandato)
- **Storage:** 100GB+ SSD
- **Bandwidth:** Illimitato (video streaming)

### 2. Software da installare sul server
```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER

# Install Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# Install Git
sudo apt install git -y

# Install Certbot (for SSL)
sudo apt install certbot -y
```

### 3. Dominio e DNS
- Registrare dominio (es. `yourdomain.com`)
- Configurare DNS records:
  ```
  A     @             -> YOUR_SERVER_IP
  A     www           -> YOUR_SERVER_IP
  A     api           -> YOUR_SERVER_IP
  ```

---

## 🔧 FASE 1: PREPARAZIONE (30 min)

### Step 1.1: Clone Repository
```bash
cd /app
git clone https://github.com/yourusername/media-center-arti-marziali.git
cd media-center-arti-marziali
```

### Step 1.2: Configurazione Environment Variables
```bash
# Copy template
cp .env.production.template .env.production

# Edit with your values
nano .env.production
```

**Variabili CRITICHE da configurare:**
```bash
# Security
SECRET_KEY=<generate with: openssl rand -hex 32>

# Database
DATABASE_URL=postgresql://martial_user:STRONG_PASSWORD@postgres:5432/martial_arts_prod

# Stripe
STRIPE_SECRET_KEY=sk_live_...
STRIPE_PUBLISHABLE_KEY=pk_live_...
STRIPE_WEBHOOK_SECRET=whsec_...

# S3 or CloudFlare R2
AWS_ACCESS_KEY_ID=...
AWS_SECRET_ACCESS_KEY=...
S3_BUCKET_NAME=martial-arts-videos-prod

# Email (SendGrid)
SENDGRID_API_KEY=SG....
EMAIL_FROM=noreply@yourdomain.com

# Sentry
SENTRY_DSN=https://...@sentry.io/...

# Domain
DOMAIN=yourdomain.com
BACKEND_URL=https://api.yourdomain.com
FRONTEND_URL=https://yourdomain.com
```

### Step 1.3: Generare SECRET_KEY
```bash
openssl rand -hex 32
# Copiare l'output in .env.production SECRET_KEY=
```

### Step 1.4: Update Nginx Configuration
```bash
# Edit domain in nginx config
sed -i 's/yourdomain.com/YOUR_ACTUAL_DOMAIN/g' nginx/conf.d/martial-arts.conf
```

---

## 🔐 FASE 2: SSL CERTIFICATES (15 min)

### Step 2.1: Generate SSL with Let's Encrypt
```bash
# Stop any service on port 80
sudo systemctl stop nginx 2>/dev/null || true

# Generate certificates
sudo certbot certonly --standalone \
  -d yourdomain.com \
  -d www.yourdomain.com \
  -d api.yourdomain.com \
  --email admin@yourdomain.com \
  --agree-tos \
  --non-interactive

# Verify certificates
sudo ls -la /etc/letsencrypt/live/yourdomain.com/
```

### Step 2.2: Auto-Renewal Setup
```bash
# Add cron job for auto-renewal
sudo crontab -e

# Add this line:
0 3 * * * certbot renew --quiet && docker-compose -f /app/media-center-arti-marziali/docker-compose.prod.yml restart nginx
```

---

## 🗄️ FASE 3: DATABASE SETUP (20 min)

### Option A: Managed PostgreSQL (RACCOMANDATO)
**DigitalOcean / AWS RDS / Heroku Postgres**

1. Crea database managed
2. Ottieni connection string
3. Aggiungi in `.env.production`:
   ```
   DATABASE_URL=postgresql://user:pass@host:port/dbname
   ```

### Option B: Self-Hosted PostgreSQL (Docker)
Database già incluso in `docker-compose.prod.yml`

```bash
# Set strong password in .env.production
DB_PASSWORD=<generate-strong-password>
```

### Step 3.1: Initialize Database
```bash
# Start only postgres
docker-compose -f docker-compose.prod.yml up -d postgres

# Wait for postgres to be ready
sleep 10

# Run migrations
docker-compose -f docker-compose.prod.yml run --rm backend alembic upgrade head

# Create admin user (optional)
docker-compose -f docker-compose.prod.yml run --rm backend python -c "
from models.user import User
from core.database import SessionLocal
from core.security import get_password_hash
import uuid

db = SessionLocal()
admin = User(
    id=uuid.uuid4(),
    email='admin@yourdomain.com',
    username='admin',
    hashed_password=get_password_hash('CHANGE_THIS_PASSWORD'),
    is_admin=True,
    is_superuser=True,
    email_verified=True
)
db.add(admin)
db.commit()
print('Admin user created!')
"
```

---

## 🐳 FASE 4: DEPLOY APPLICATION (30 min)

### Step 4.1: Build Images
```bash
cd /app/media-center-arti-marziali

# Build all images
docker-compose -f docker-compose.prod.yml build

# This will take 10-15 minutes
```

### Step 4.2: Start All Services
```bash
# Start in detached mode
docker-compose -f docker-compose.prod.yml up -d

# Check logs
docker-compose -f docker-compose.prod.yml logs -f
```

### Step 4.3: Verify Services
```bash
# Check all containers are running
docker-compose -f docker-compose.prod.yml ps

# Should see:
# nginx          - Up
# backend        - Up (healthy)
# frontend       - Up (healthy)
# postgres       - Up (healthy)
# redis          - Up (healthy)
# celery-worker  - Up
# celery-beat    - Up
```

### Step 4.4: Health Checks
```bash
# Backend health
curl http://localhost:8000/health

# Frontend (through nginx)
curl http://localhost/

# API (through nginx)
curl http://localhost/api/health
```

---

## ✅ FASE 5: VERIFICATION (15 min)

### Step 5.1: Test Public URLs
```bash
# Backend API (should return health status)
curl https://api.yourdomain.com/health

# Frontend (should return HTML)
curl https://yourdomain.com

# API Docs
curl https://api.yourdomain.com/docs
```

### Step 5.2: Test Key Endpoints
```bash
# Registration
curl -X POST https://api.yourdomain.com/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "username": "testuser",
    "password": "SecurePassword123!"
  }'

# Login
curl -X POST https://api.yourdomain.com/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "SecurePassword123!"
  }'
```

### Step 5.3: Test Stripe Webhook
```bash
# Configure webhook in Stripe Dashboard:
# URL: https://api.yourdomain.com/api/v1/webhooks/stripe
# Events: payment_intent.succeeded, customer.subscription.updated, etc.

# Get webhook secret from Stripe and add to .env.production
STRIPE_WEBHOOK_SECRET=whsec_...

# Restart backend to apply
docker-compose -f docker-compose.prod.yml restart backend
```

---

## 🔧 FASE 6: MONITORING & LOGGING (20 min)

### Step 6.1: Sentry Setup
1. Create project on sentry.io
2. Get DSN
3. Add to `.env.production`:
   ```
   SENTRY_DSN=https://...@sentry.io/...
   ```
4. Restart backend

### Step 6.2: View Logs
```bash
# All services
docker-compose -f docker-compose.prod.yml logs -f

# Specific service
docker-compose -f docker-compose.prod.yml logs -f backend
docker-compose -f docker-compose.prod.yml logs -f nginx

# Save logs to file
docker-compose -f docker-compose.prod.yml logs > deployment-logs.txt
```

### Step 6.3: Resource Monitoring
```bash
# Container stats
docker stats

# Disk usage
df -h

# Database size
docker-compose -f docker-compose.prod.yml exec postgres psql -U martial_user -d martial_arts_prod -c "\l+"
```

---

## 🔄 FASE 7: CI/CD SETUP (Optional - 15 min)

### Step 7.1: GitHub Secrets
Go to GitHub → Settings → Secrets and variables → Actions

Add:
```
SSH_PRIVATE_KEY       = <private key>
SSH_KNOWN_HOSTS       = <ssh-keyscan your-server.com>
SERVER_HOST           = your-server.com
SERVER_USER           = ubuntu
PRODUCTION_URL        = https://yourdomain.com
SLACK_WEBHOOK_URL     = <optional>
```

### Step 7.2: Generate Deploy Key
```bash
# On your local machine
ssh-keygen -t ed25519 -C "github-actions@martial-arts" -f ~/.ssh/deploy_key

# Add public key to server
cat ~/.ssh/deploy_key.pub
# Copy and add to server: ~/.ssh/authorized_keys

# Add private key to GitHub Secrets
cat ~/.ssh/deploy_key
# Copy entire content to SSH_PRIVATE_KEY secret
```

### Step 7.3: Test Workflow
```bash
# Push to main branch
git add .
git commit -m "Initial production deployment"
git push origin main

# Check GitHub Actions tab
# Workflow should run automatically
```

---

## 📦 FASE 8: BACKUP SETUP (15 min)

### Step 8.1: Database Backup Script
```bash
# Create backup script
sudo nano /usr/local/bin/backup-martial-arts-db.sh
```

```bash
#!/bin/bash
BACKUP_DIR="/backups/martial-arts"
DATE=$(date +%Y%m%d_%H%M%S)
FILENAME="martial_arts_$DATE.sql"

mkdir -p $BACKUP_DIR

docker-compose -f /app/media-center-arti-marziali/docker-compose.prod.yml \
  exec -T postgres pg_dump -U martial_user martial_arts_prod > "$BACKUP_DIR/$FILENAME"

gzip "$BACKUP_DIR/$FILENAME"

# Keep only last 30 days
find $BACKUP_DIR -name "*.sql.gz" -mtime +30 -delete

echo "Backup completed: $FILENAME.gz"
```

```bash
# Make executable
sudo chmod +x /usr/local/bin/backup-martial-arts-db.sh

# Add cron job (daily at 2 AM)
sudo crontab -e
0 2 * * * /usr/local/bin/backup-martial-arts-db.sh
```

### Step 8.2: Test Backup
```bash
sudo /usr/local/bin/backup-martial-arts-db.sh
ls -lh /backups/martial-arts/
```

---

## 🔧 COMMON OPERATIONS

### Update Application
```bash
cd /app/media-center-arti-marziali
git pull origin main
docker-compose -f docker-compose.prod.yml pull
docker-compose -f docker-compose.prod.yml up -d --no-deps --build backend frontend
docker-compose -f docker-compose.prod.yml exec backend alembic upgrade head
```

### Restart Services
```bash
# All services
docker-compose -f docker-compose.prod.yml restart

# Specific service
docker-compose -f docker-compose.prod.yml restart backend
```

### View Logs
```bash
docker-compose -f docker-compose.prod.yml logs -f --tail=100
```

### Database Console
```bash
docker-compose -f docker-compose.prod.yml exec postgres psql -U martial_user -d martial_arts_prod
```

### Redis Console
```bash
docker-compose -f docker-compose.prod.yml exec redis redis-cli
```

### Scale Celery Workers
```bash
docker-compose -f docker-compose.prod.yml up -d --scale celery-worker=4
```

---

## 🚨 TROUBLESHOOTING

### Problem: Containers not starting
```bash
# Check logs
docker-compose -f docker-compose.prod.yml logs

# Check specific service
docker-compose -f docker-compose.prod.yml logs backend

# Restart all
docker-compose -f docker-compose.prod.yml down
docker-compose -f docker-compose.prod.yml up -d
```

### Problem: Database connection errors
```bash
# Check postgres is running
docker-compose -f docker-compose.prod.yml ps postgres

# Check DATABASE_URL in .env.production
cat .env.production | grep DATABASE_URL

# Test connection
docker-compose -f docker-compose.prod.yml exec postgres psql -U martial_user -d martial_arts_prod -c "SELECT 1;"
```

### Problem: SSL certificate issues
```bash
# Renew certificates
sudo certbot renew --force-renewal

# Restart nginx
docker-compose -f docker-compose.prod.yml restart nginx
```

### Problem: Out of disk space
```bash
# Clean Docker images
docker system prune -a

# Clean logs
docker-compose -f docker-compose.prod.yml logs --tail=0 -f > /dev/null &
```

---

## 📊 MONITORING CHECKLIST

### Daily
- [ ] Check Sentry for errors
- [ ] Review application logs
- [ ] Monitor disk space
- [ ] Check backup completion

### Weekly
- [ ] Review performance metrics
- [ ] Check database size
- [ ] Review security logs
- [ ] Update dependencies

### Monthly
- [ ] Test backup restoration
- [ ] Review SSL certificate expiry
- [ ] Audit user accounts
- [ ] Performance optimization

---

## 🎯 SUCCESS CRITERIA

✅ All containers running and healthy
✅ HTTPS working on all domains
✅ Database migrations applied
✅ Health endpoints responding
✅ Stripe webhooks configured
✅ Email sending working
✅ Backups scheduled
✅ Monitoring active (Sentry)
✅ CI/CD pipeline working
✅ Admin user can login

---

## 📞 SUPPORT

- GitHub Issues: https://github.com/yourusername/media-center-arti-marziali/issues
- Email: tech@yourdomain.com

---

**DEPLOYMENT COMPLETE! 🎉**

Your Media Center Arti Marziali platform is now live at:
- **Frontend:** https://yourdomain.com
- **API:** https://api.yourdomain.com
- **API Docs:** https://api.yourdomain.com/docs
