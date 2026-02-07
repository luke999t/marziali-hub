# US-003: Backend Health Check & Startup

## Overview
Ensure backend starts cleanly and health endpoint works.

## Tasks

### 1. Fix main.py imports
- [ ] Verify all router imports work
- [ ] Remove/comment broken imports temporarily
- [ ] Add proper exception handling for optional modules

### 2. Health Endpoint
```python
@app.get("/health")
def health_check():
    return {"status": "ok", "timestamp": datetime.utcnow().isoformat()}
```

### 3. Startup Test
```bash
cd backend
uvicorn main:app --port 8000
# Should see: "Application startup complete"
# No ImportError or ModuleNotFoundError
```

### 4. Swagger UI
- [ ] Access http://localhost:8000/docs
- [ ] All endpoints visible
- [ ] No 500 errors on page load

## Acceptance Criteria

- [ ] uvicorn main:app --port 8000 starts without errors
- [ ] GET /health returns 200 OK
- [ ] GET /docs shows Swagger UI
- [ ] All routers load without import errors

## Estimated Effort: 2 hours
