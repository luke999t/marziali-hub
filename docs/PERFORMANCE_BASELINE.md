# Performance Baseline - Media Center Arti Marziali

**Data**: 2025-01-28
**Versione**: 1.0.0
**Tool**: Locust 2.20.1 + Prometheus + Grafana

---

## Ambiente di Test

### Hardware
| Componente | Specifica |
|------------|-----------|
| Server | Local Development / CI Runner |
| CPU | 4+ cores recommended |
| RAM | 8GB+ recommended |
| Network | Localhost / Docker Network |

### Software Stack
| Servizio | Versione | Porta |
|----------|----------|-------|
| FastAPI Backend | 0.109.0 | 8000 |
| PostgreSQL | 15.x | 5432 |
| Redis | 7.x | 6379 |
| Prometheus | 2.48.0 | 9090 |
| Grafana | 10.2.0 | 3000 |
| Locust | 2.20.1 | 8089 |

### Configurazione Test
```yaml
Backend:
  workers: 4 (uvicorn)
  max_connections_db: 20
  redis_pool_size: 10

Locust:
  host: http://localhost:8000
  users_distribution:
    ViewerUser: 70%      # Browsing behavior
    AuthenticatedUser: 20%  # Logged-in actions
    APITesterUser: 10%   # API stress testing
```

---

## Risultati Test di Carico

### 1. Baseline Test (100 utenti)

**Obiettivo**: Verificare stabilità sotto carico normale

| Metrica | Valore | Target | Status |
|---------|--------|--------|--------|
| Requests/sec | - | > 100 | ⏳ |
| Avg Response Time | - | < 200ms | ⏳ |
| P95 Response Time | - | < 500ms | ⏳ |
| P99 Response Time | - | < 1000ms | ⏳ |
| Error Rate | - | < 1% | ⏳ |
| CPU Usage | - | < 60% | ⏳ |
| Memory Usage | - | < 70% | ⏳ |

**Endpoint Performance**:
| Endpoint | Avg (ms) | P95 (ms) | P99 (ms) | RPS |
|----------|----------|----------|----------|-----|
| GET /api/v1/videos/ | - | - | - | - |
| GET /api/v1/videos/trending | - | - | - | - |
| GET /api/v1/videos/[id] | - | - | - | - |
| POST /api/v1/auth/login | - | - | - | - |
| GET /health | - | - | - | - |

---

### 2. Normal Load Test (500 utenti)

**Obiettivo**: Simulare traffico giornaliero tipico

| Metrica | Valore | Target | Status |
|---------|--------|--------|--------|
| Requests/sec | - | > 300 | ⏳ |
| Avg Response Time | - | < 300ms | ⏳ |
| P95 Response Time | - | < 800ms | ⏳ |
| P99 Response Time | - | < 1500ms | ⏳ |
| Error Rate | - | < 2% | ⏳ |
| CPU Usage | - | < 75% | ⏳ |
| Memory Usage | - | < 80% | ⏳ |

**Endpoint Performance**:
| Endpoint | Avg (ms) | P95 (ms) | P99 (ms) | RPS |
|----------|----------|----------|----------|-----|
| GET /api/v1/videos/ | - | - | - | - |
| GET /api/v1/videos/trending | - | - | - | - |
| GET /api/v1/videos/[id] | - | - | - | - |
| POST /api/v1/auth/login | - | - | - | - |
| GET /health | - | - | - | - |

---

### 3. Peak Load Test (1000 utenti)

**Obiettivo**: Target principale - 1000 utenti concorrenti

| Metrica | Valore | Target | Status |
|---------|--------|--------|--------|
| Requests/sec | - | > 500 | ⏳ |
| Avg Response Time | - | < 500ms | ⏳ |
| P95 Response Time | - | < 1500ms | ⏳ |
| P99 Response Time | - | < 3000ms | ⏳ |
| Error Rate | - | < 5% | ⏳ |
| CPU Usage | - | < 85% | ⏳ |
| Memory Usage | - | < 85% | ⏳ |

**Endpoint Performance**:
| Endpoint | Avg (ms) | P95 (ms) | P99 (ms) | RPS |
|----------|----------|----------|----------|-----|
| GET /api/v1/videos/ | - | - | - | - |
| GET /api/v1/videos/trending | - | - | - | - |
| GET /api/v1/videos/[id] | - | - | - | - |
| POST /api/v1/auth/login | - | - | - | - |
| GET /health | - | - | - | - |

---

### 4. Stress Test (2000 utenti)

**Obiettivo**: Identificare punto di rottura

| Metrica | Valore | Target | Status |
|---------|--------|--------|--------|
| Requests/sec | - | > 300 | ⏳ |
| Avg Response Time | - | < 2000ms | ⏳ |
| P95 Response Time | - | < 5000ms | ⏳ |
| P99 Response Time | - | < 10000ms | ⏳ |
| Error Rate | - | < 10% | ⏳ |
| CPU Usage | - | < 95% | ⏳ |
| Memory Usage | - | < 95% | ⏳ |

**Breaking Point Analysis**:
| Metrica | Valore |
|---------|--------|
| Max Users Before Degradation | - |
| Max Users Before Failure | - |
| First Error Threshold | - |
| Recovery Time | - |

---

## Bottleneck Identificati

### Database
| Issue | Severità | Rilevato a N utenti |
|-------|----------|---------------------|
| Connection pool exhaustion | - | - |
| Slow queries | - | - |
| Lock contention | - | - |

### Application
| Issue | Severità | Rilevato a N utenti |
|-------|----------|---------------------|
| Memory leak | - | - |
| CPU saturation | - | - |
| Thread starvation | - | - |

### Network
| Issue | Severità | Rilevato a N utenti |
|-------|----------|---------------------|
| Bandwidth saturation | - | - |
| Connection timeout | - | - |
| DNS resolution | - | - |

---

## Raccomandazioni

### Immediate (Pre-Production)
- [ ] Configurare connection pooling PostgreSQL (min 20, max 100)
- [ ] Abilitare Redis caching per endpoint frequenti
- [ ] Implementare rate limiting (100 req/min per IP)
- [ ] Configurare Gunicorn con workers = 2 * CPU + 1

### Short-term (Post-Launch)
- [ ] Implementare caching distribuito
- [ ] Aggiungere CDN per contenuti statici
- [ ] Ottimizzare query N+1 identificate
- [ ] Implementare pagination cursor-based

### Long-term (Scaling)
- [ ] Horizontal scaling con load balancer
- [ ] Database read replicas
- [ ] Microservices split per video processing
- [ ] Kubernetes deployment per auto-scaling

---

## Comandi per Eseguire i Test

### Avvio Stack Monitoring
```bash
# Avvia Prometheus + Grafana + Alertmanager
docker-compose -f docker-compose.monitoring.yml up -d

# Verifica status
docker-compose -f docker-compose.monitoring.yml ps

# Dashboard Grafana: http://localhost:3000 (admin/admin)
# Prometheus: http://localhost:9090
```

### Esecuzione Load Tests
```bash
# Installa dipendenze
cd load_tests
pip install -r requirements.txt  # Se esiste, altrimenti: pip install locust

# Test Web UI (consigliato per primo test)
locust -f locustfile.py --host=http://localhost:8000

# Test Headless - 100 utenti
locust -f locustfile.py --host=http://localhost:8000 \
  --headless -u 100 -r 10 -t 5m \
  --html=reports/baseline_100.html

# Test Headless - 500 utenti
locust -f locustfile.py --host=http://localhost:8000 \
  --headless -u 500 -r 50 -t 10m \
  --html=reports/normal_500.html

# Test Headless - 1000 utenti (TARGET)
locust -f locustfile.py --host=http://localhost:8000 \
  --headless -u 1000 -r 100 -t 15m \
  --html=reports/peak_1000.html

# Test Headless - 2000 utenti (STRESS)
locust -f locustfile.py --host=http://localhost:8000 \
  --headless -u 2000 -r 200 -t 10m \
  --html=reports/stress_2000.html
```

### Tag-based Tests
```bash
# Solo test di browse (ViewerUser)
locust -f locustfile.py --host=http://localhost:8000 \
  --tags browse --headless -u 500 -r 50 -t 5m

# Solo test autenticati
locust -f locustfile.py --host=http://localhost:8000 \
  --tags auth --headless -u 200 -r 20 -t 5m

# Solo test video
locust -f locustfile.py --host=http://localhost:8000 \
  --tags videos --headless -u 300 -r 30 -t 5m
```

---

## Metriche Prometheus Query

### Request Rate
```promql
rate(http_requests_total{handler!~"/health|/metrics"}[5m])
```

### Response Time P95
```promql
histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m]))
```

### Error Rate
```promql
sum(rate(http_requests_total{status=~"5.."}[5m])) / sum(rate(http_requests_total[5m])) * 100
```

### Active Connections
```promql
http_requests_inprogress
```

---

## Note Esecuzione Test

| Data | Test | Utenti | Durata | Note |
|------|------|--------|--------|------|
| 2025-01-28 | Setup | - | - | Infrastructure created |
| - | - | - | - | - |
| - | - | - | - | - |

---

## Grafana Dashboard

Il dashboard preconfigurato include:
- **Request Rate Panel**: Richieste al secondo per endpoint
- **Response Time Panel**: Latenze P50, P95, P99
- **Error Rate Panel**: Percentuale errori 4xx e 5xx
- **System Metrics**: CPU, Memory, Network I/O
- **Active Connections**: Connessioni in-progress

Accesso: http://localhost:3000
Credenziali default: admin / admin

---

*Documento generato: 2025-01-28*
*Prossimo update: Dopo esecuzione test di carico*
