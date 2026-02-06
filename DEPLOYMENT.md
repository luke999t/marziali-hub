# Deployment Guide - Media Center Arti Marziali

Complete production deployment guide using Docker, Docker Compose, and Nginx.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Environment Setup](#environment-setup)
3. [Docker Deployment](#docker-deployment)
4. [SSL/TLS Configuration](#ssltls-configuration)
5. [Database Migration](#database-migration)
6. [Monitoring](#monitoring)
7. [Backup & Recovery](#backup--recovery)
8. [Scaling](#scaling)
9. [Troubleshooting](#troubleshooting)

---

## Prerequisites

### System Requirements

- **Server**: Ubuntu 22.04 LTS or similar (4GB RAM minimum, 8GB recommended)
- **Docker**: Version 24.0 or higher
- **Docker Compose**: Version 2.20 or higher
- **Domain**: Configured DNS pointing to your server
- **Ports**: 80 (HTTP), 443 (HTTPS) open

### Installation

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Install Docker Compose
sudo apt install docker-compose-plugin -y

# Verify installations
docker --version
docker compose version
```

---

## Environment Setup

### 1. Clone Repository

```bash
git clone https://github.com/yourusername/media-center-arti-marziali.git
cd media-center-arti-marziali
```

### 2. Configure Environment

```bash
# Copy environment template
cp .env.example .env

# Edit environment variables
nano .env
```

### Required Variables

Update these **mandatory** values in `.env`:

```env
# Strong random secret key (generate with: openssl rand -base64 32)
SECRET_KEY=your-super-secret-key-here

# Strong database password
POSTGRES_PASSWORD=your-strong-db-password

# Your domain
CORS_ORIGINS=https://yourdomain.com

# Backend URL for frontend
NEXT_PUBLIC_API_URL=https://yourdomain.com/api
```

---

## Docker Deployment

### Development Mode

```bash
# Start all services
docker compose up -d

# View logs
docker compose logs -f

# Stop services
docker compose down
```

### Production Mode

```bash
# Build images
docker compose build --no-cache

# Start services in production
docker compose up -d

# Check status
docker compose ps

# View specific service logs
docker compose logs backend -f
docker compose logs frontend -f
docker compose logs nginx -f
```

### Service URLs

- **Frontend**: http://localhost (via nginx)
- **Backend API**: http://localhost/api
- **Database**: localhost:5432
- **Redis**: localhost:6379

---

## SSL/TLS Configuration

### Using Let's Encrypt (Recommended)

```bash
# Install certbot
sudo apt install certbot python3-certbot-nginx -y

# Generate SSL certificate
sudo certbot certonly --standalone \
  -d yourdomain.com \
  -d www.yourdomain.com \
  --email your@email.com \
  --agree-tos

# Copy certificates to nginx directory
sudo mkdir -p nginx/ssl
sudo cp /etc/letsencrypt/live/yourdomain.com/fullchain.pem nginx/ssl/cert.pem
sudo cp /etc/letsencrypt/live/yourdomain.com/privkey.pem nginx/ssl/key.pem

# Update nginx configuration
nano nginx/conf.d/default.conf
```

Uncomment SSL lines in `nginx/conf.d/default.conf`:

```nginx
# Uncomment these lines:
listen 443 ssl http2;
ssl_certificate /etc/nginx/ssl/cert.pem;
ssl_certificate_key /etc/nginx/ssl/key.pem;
```

```bash
# Restart nginx
docker compose restart nginx

# Setup auto-renewal
sudo certbot renew --dry-run
```

---

## Database Migration

### Initial Setup

```bash
# Run database migrations
docker compose exec backend alembic upgrade head

# Create admin user
docker compose exec backend python scripts/create_admin.py
```

### Backup Database

```bash
# Create backup
docker compose exec postgres pg_dump -U martial_user martial_arts_db > backup.sql

# With timestamp
docker compose exec postgres pg_dump -U martial_user martial_arts_db > backup_$(date +%Y%m%d_%H%M%S).sql
```

### Restore Database

```bash
# Restore from backup
cat backup.sql | docker compose exec -T postgres psql -U martial_user martial_arts_db
```

---

## Monitoring

### Health Checks

```bash
# Check service health
docker compose ps

# Backend health
curl http://localhost/health

# Database health
docker compose exec postgres pg_isready -U martial_user

# Redis health
docker compose exec redis redis-cli ping
```

### Logs

```bash
# All logs
docker compose logs -f

# Specific service
docker compose logs -f backend

# Last 100 lines
docker compose logs --tail=100 backend

# Save logs to file
docker compose logs > logs_$(date +%Y%m%d).txt
```

### Resource Usage

```bash
# Container stats
docker stats

# Disk usage
docker system df

# Cleanup unused resources
docker system prune -a
```

---

## Backup & Recovery

### Automated Backups

Create backup script `scripts/backup.sh`:

```bash
#!/bin/bash
BACKUP_DIR="/backups"
DATE=$(date +%Y%m%d_%H%M%S)

# Database backup
docker compose exec -T postgres pg_dump -U martial_user martial_arts_db > $BACKUP_DIR/db_$DATE.sql

# Compress
gzip $BACKUP_DIR/db_$DATE.sql

# Keep only last 7 days
find $BACKUP_DIR -name "db_*.sql.gz" -mtime +7 -delete

echo "Backup completed: db_$DATE.sql.gz"
```

Setup cron job:

```bash
# Edit crontab
crontab -e

# Add daily backup at 2 AM
0 2 * * * /path/to/scripts/backup.sh
```

---

## Scaling

### Horizontal Scaling

Update `docker-compose.yml` to scale services:

```yaml
backend:
  deploy:
    replicas: 3
    resources:
      limits:
        cpus: '1'
        memory: 1G
```

```bash
# Scale backend
docker compose up -d --scale backend=3

# Verify
docker compose ps backend
```

### Load Balancing

Nginx automatically load balances across backend replicas:

```nginx
upstream backend {
    least_conn;
    server backend_1:8000 max_fails=3 fail_timeout=30s;
    server backend_2:8000 max_fails=3 fail_timeout=30s;
    server backend_3:8000 max_fails=3 fail_timeout=30s;
}
```

---

## Troubleshooting

### Common Issues

#### 1. Port Already in Use

```bash
# Find process using port
sudo lsof -i :80
sudo lsof -i :443

# Kill process
sudo kill -9 <PID>
```

#### 2. Container Won't Start

```bash
# Check logs
docker compose logs backend

# Remove and recreate
docker compose down
docker compose up -d --force-recreate
```

#### 3. Database Connection Error

```bash
# Check postgres is running
docker compose ps postgres

# Test connection
docker compose exec backend python -c "from core.database import test_connection; test_connection()"

# Reset database
docker compose down -v
docker compose up -d
```

#### 4. Nginx Configuration Error

```bash
# Test nginx config
docker compose exec nginx nginx -t

# Reload nginx
docker compose exec nginx nginx -s reload
```

### Reset Everything

```bash
# Stop and remove all
docker compose down -v

# Remove images
docker compose down --rmi all

# Start fresh
docker compose up -d --build
```

---

## Performance Tuning

### Database Optimization

Add to postgres service in `docker-compose.yml`:

```yaml
postgres:
  command:
    - postgres
    - -c
    - max_connections=200
    - -c
    - shared_buffers=256MB
    - -c
    - effective_cache_size=1GB
```

### Redis Optimization

Add to redis service:

```yaml
redis:
  command: redis-server --maxmemory 256mb --maxmemory-policy allkeys-lru
```

---

## Security Checklist

- [ ] Change all default passwords
- [ ] Generate strong SECRET_KEY
- [ ] Configure firewall (ufw)
- [ ] Enable SSL/TLS
- [ ] Setup automated backups
- [ ] Configure Sentry for error tracking
- [ ] Enable rate limiting
- [ ] Regular security updates
- [ ] Monitor logs
- [ ] Restrict database access

---

## Production Checklist

### Before Deploy

- [ ] Environment variables configured
- [ ] SSL certificates generated
- [ ] Database backed up
- [ ] All tests passing
- [ ] Sentry configured
- [ ] Monitoring setup
- [ ] Backup strategy defined

### After Deploy

- [ ] SSL working (check https://)
- [ ] Health endpoints responding
- [ ] Database migrations applied
- [ ] Admin user created
- [ ] Logs being generated
- [ ] Backups running
- [ ] Performance metrics checked

---

## Commands Cheat Sheet

```bash
# Start services
docker compose up -d

# Stop services
docker compose down

# Rebuild and restart
docker compose up -d --build

# View logs
docker compose logs -f [service]

# Execute command in container
docker compose exec [service] [command]

# Scale service
docker compose up -d --scale backend=3

# Remove everything
docker compose down -v --rmi all

# Database backup
docker compose exec postgres pg_dump -U martial_user martial_arts_db > backup.sql

# Database restore
cat backup.sql | docker compose exec -T postgres psql -U martial_user martial_arts_db
```

---

## Support

For issues or questions:
- Check logs: `docker compose logs`
- Review this guide
- Check GitHub issues
- Contact: support@yourdomain.com

---

## License

MIT License - See LICENSE file for details

---

**Last Updated**: November 2025
**Version**: 1.0.0
