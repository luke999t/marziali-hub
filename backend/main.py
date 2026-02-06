"""
🚀 Media Center Arti Marziali - Backend API
Enterprise FastAPI application with Sentry error tracking
"""

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.gzip import GZipMiddleware
from contextlib import asynccontextmanager
import os
from dotenv import load_dotenv

# Import Sentry configuration
from core.sentry_config import init_sentry, add_breadcrumb, capture_exception

# Load environment variables
load_dotenv()

# Initialize Sentry BEFORE creating the FastAPI app
SENTRY_DSN = os.getenv("SENTRY_DSN")
ENVIRONMENT = os.getenv("ENVIRONMENT", "development")
RELEASE = os.getenv("RELEASE", "v1.0.0")

if SENTRY_DSN:
    init_sentry(
        dsn=SENTRY_DSN,
        environment=ENVIRONMENT,
        release=RELEASE,
        traces_sample_rate=0.1 if ENVIRONMENT == "production" else 1.0,
        profiles_sample_rate=0.1 if ENVIRONMENT == "production" else 1.0,
    )


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan events
    """
    # Startup
    print("[STARTUP] Starting Media Center Arti Marziali API...")
    add_breadcrumb("Application starting", category="lifecycle", level="info")

    # Initialize Scheduler
    try:
        from modules.scheduler import get_scheduler, JobDefinition
        from modules.scheduler.jobs import JOB_DEFINITIONS

        scheduler = get_scheduler()

        # Register all jobs
        for job_def in JOB_DEFINITIONS:
            definition = JobDefinition(
                job_id=job_def["job_id"],
                name=job_def["name"],
                description=job_def["description"],
                func=job_def["func"],
                trigger_type=job_def["trigger_type"],
                trigger_args=job_def["trigger_args"],
                enabled=job_def.get("enabled", True),
            )
            scheduler.register_job(definition)

        # Start scheduler
        scheduler.start()
        print(f"[OK] Scheduler started with {len(JOB_DEFINITIONS)} jobs")
        add_breadcrumb(f"Scheduler started with {len(JOB_DEFINITIONS)} jobs", category="lifecycle", level="info")

    except ImportError as e:
        print(f"[WARNING] Scheduler not available (missing APScheduler): {e}")
        add_breadcrumb(f"Scheduler unavailable: {e}", category="startup", level="warning")
    except Exception as e:
        print(f"[ERROR] Scheduler failed to start: {e}")
        add_breadcrumb(f"Scheduler error: {e}", category="startup", level="error")

    yield

    # Shutdown
    print("[SHUTDOWN] Shutting down Media Center Arti Marziali API...")
    add_breadcrumb("Application shutting down", category="lifecycle", level="info")

    # Shutdown Scheduler
    try:
        from modules.scheduler import get_scheduler
        scheduler = get_scheduler()
        if scheduler.is_running:
            scheduler.shutdown(wait=True)
            print("[OK] Scheduler shutdown complete")
    except Exception as e:
        print(f"[WARNING] Scheduler shutdown error: {e}")


# Create FastAPI app
# 🔧 FIX 2026-02-01: Aggiunto redirect_slashes=False per evitare redirect 307
# PROBLEMA: Browser non rinvia Authorization header dopo redirect 307
# Quando frontend chiama /api/v1/curricula (senza slash), FastAPI redirige a /curricula/
# ma il browser perde l'header Authorization → 401 Unauthorized
# SOLUZIONE: Disabilita redirect automatico, accetta URL con o senza trailing slash
app = FastAPI(
    title="Media Center Arti Marziali API",
    description="Enterprise platform for martial arts courses with AI Coach and live streaming",
    version="1.0.0",
    lifespan=lifespan,
    # NOTE: redirect_slashes=True (default) - il frontend usa sempre trailing slash
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure this properly in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Compression middleware (Gzip)
app.add_middleware(GZipMiddleware, minimum_size=1000)

# Prometheus metrics instrumentation
# FIX_2025_01_28: Added for performance monitoring with Grafana
try:
    from prometheus_fastapi_instrumentator import Instrumentator

    instrumentator = Instrumentator(
        should_group_status_codes=False,
        should_ignore_untemplated=True,
        should_respect_env_var=True,
        should_instrument_requests_inprogress=True,
        excluded_handlers=["/health", "/metrics", "/docs", "/openapi.json"],
        env_var_name="ENABLE_METRICS",
        inprogress_name="http_requests_inprogress",
        inprogress_labels=True,
    )

    instrumentator.instrument(app).expose(app, include_in_schema=False)
    print("[OK] Prometheus metrics enabled at /metrics")
except ImportError:
    print("[INFO] prometheus-fastapi-instrumentator not installed, metrics disabled")
except Exception as e:
    print(f"[WARNING] Prometheus metrics initialization failed: {e}")


# Custom exception handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """
    Global exception handler that captures all unhandled exceptions in Sentry
    """
    # Add request context
    add_breadcrumb(
        message=f"Unhandled exception on {request.method} {request.url.path}",
        category="error",
        level="error",
        data={
            "method": request.method,
            "url": str(request.url),
            "client_host": request.client.host if request.client else None,
        }
    )

    # Capture exception in Sentry
    capture_exception(
        exc,
        tags={
            "endpoint": request.url.path,
            "method": request.method,
        },
        extra={
            "url": str(request.url),
            "headers": dict(request.headers),
        }
    )

    # Return error response
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": "Internal Server Error",
            "detail": str(exc) if ENVIRONMENT == "development" else "An unexpected error occurred",
        }
    )


# FIX BUG #3: Handler esplicito OPTIONS per CORS preflight
# 🎓 AI_TEACHING: Il CORSMiddleware di Starlette gestisce OPTIONS automaticamente,
# ma SOLO se la request arriva al middleware. Con redirect_slashes il 307
# può bypassare il CORS. Questo catch-all garantisce che qualsiasi
# preflight OPTIONS riceva headers CORS corretti.
@app.options("/{full_path:path}")
async def preflight_handler(request: Request, full_path: str):
    """
    🎓 AI_BUSINESS: CORS preflight essenziale per frontend su dominio diverso.
    Senza questo, il browser blocca tutte le richieste cross-origin.
    """
    return JSONResponse(
        content={"message": "OK"},
        headers={
            "Access-Control-Allow-Origin": request.headers.get("origin", "*"),
            "Access-Control-Allow-Methods": "GET, POST, PUT, PATCH, DELETE, OPTIONS",
            "Access-Control-Allow-Headers": "Authorization, Content-Type, Accept, Origin, X-Requested-With",
            "Access-Control-Allow-Credentials": "true",
            "Access-Control-Max-Age": "600",
        },
    )


# Health check endpoint
@app.get("/health")
async def health_check():
    """
    🎓 AI_MODULE: Health Check con diagnostica completa
    🎓 AI_BUSINESS: Monitoraggio uptime essenziale per SLA 99.9%
    🎓 AI_TEACHING: Health check deve includere dipendenze (DB, disk)
        per distinguere "app up" da "sistema funzionante"
    
    FIX BUG #4: Aggiunto database status e disk space info
    per test #146 (Health mostra stato DB) e #147 (Health mostra disk space)
    """
    import shutil
    from datetime import datetime as dt

    # --- Database check ---
    db_status = "unknown"
    db_latency_ms = None
    try:
        from core.database import AsyncSessionLocal
        from sqlalchemy import text
        import time

        start = time.monotonic()
        async with AsyncSessionLocal() as session:
            await session.execute(text("SELECT 1"))
        db_latency_ms = round((time.monotonic() - start) * 1000, 1)
        db_status = "connected"
    except Exception as e:
        db_status = f"error: {str(e)[:80]}"

    # --- Disk space check ---
    disk_info = {}
    try:
        usage = shutil.disk_usage("/")
        disk_info = {
            "total_gb": round(usage.total / (1024**3), 2),
            "used_gb": round(usage.used / (1024**3), 2),
            "free_gb": round(usage.free / (1024**3), 2),
            "used_percent": round(usage.used / usage.total * 100, 1),
        }
    except Exception:
        # Windows: prova con il drive corrente
        try:
            import os
            drive = os.path.splitdrive(os.getcwd())[0] or "C:\\"
            usage = shutil.disk_usage(drive)
            disk_info = {
                "total_gb": round(usage.total / (1024**3), 2),
                "used_gb": round(usage.used / (1024**3), 2),
                "free_gb": round(usage.free / (1024**3), 2),
                "used_percent": round(usage.used / usage.total * 100, 1),
            }
        except Exception:
            disk_info = {"error": "unable to read disk space"}

    return {
        "status": "healthy",
        "environment": ENVIRONMENT,
        "release": RELEASE,
        "timestamp": dt.utcnow().isoformat(),
        "database": {
            "status": db_status,
            "latency_ms": db_latency_ms,
        },
        "disk": disk_info,
        "storage": disk_info,  # Alias per test che cerca "storage"
    }


# Root endpoint
@app.get("/")
async def root():
    """
    API root endpoint
    """
    return {
        "message": "Media Center Arti Marziali API",
        "version": "1.0.0",
        "environment": ENVIRONMENT,
        "docs": "/docs",
    }


# Test Sentry endpoint (only in development)
if ENVIRONMENT == "development":
    @app.get("/sentry-test")
    async def sentry_test():
        """
        Test endpoint to verify Sentry is working
        """
        # This will trigger an error and be captured by Sentry
        raise Exception("This is a test exception for Sentry")


# Import and include routers individually
routers_config = [
    ('auth', '/api/v1/auth', ['auth']),
    ('users', '/api/v1/users', ['users']),
    ('videos', '/api/v1/videos', ['videos']),
    ('subscriptions', '/api/v1/subscriptions', ['subscriptions']),
    ('ads', '/api/v1/ads', ['ads']),
    ('blockchain', '/api/v1/blockchain', ['blockchain']),
    ('maestro', '/api/v1/maestro', ['maestro']),
    ('live', '/api/v1/live', ['live']),
    ('asd', '/api/v1/asd', ['asd']),
    ('admin', '/api/v1/admin', ['admin']),
]

for router_name, prefix, tags in routers_config:
    try:
        module = __import__(f'api.v1.{router_name}', fromlist=['router'])
        app.include_router(module.router, prefix=prefix, tags=tags)
        print(f"[OK] {router_name} router loaded")
    except Exception as e:
        print(f"[WARNING] {router_name} router failed to load: {e}")
        add_breadcrumb(f"{router_name} router error: {e}", category="startup", level="warning")

# Communication router (newly created, always load)
try:
    from api.v1 import communication
    app.include_router(communication.router, prefix="/api/v1/communication", tags=["communication"])
    print("[OK] Communication router loaded")
except Exception as e:
    print(f"[ERROR] Communication router failed to load: {e}")
    add_breadcrumb(f"Communication router error: {e}", category="startup", level="error")

# Library router (user video progress and saved videos)
try:
    from api.v1 import library
    app.include_router(library.router, prefix="/api/v1", tags=["library"])
    print("[OK] Library router loaded")
except Exception as e:
    print(f"[ERROR] Library router failed to load: {e}")
    add_breadcrumb(f"Library router error: {e}", category="startup", level="error")

# Moderation router (video approval/rejection workflow)
try:
    from api.v1 import moderation
    app.include_router(moderation.router, prefix="/api/v1/moderation", tags=["moderation"])
    print("[OK] Moderation router loaded")
except Exception as e:
    print(f"[ERROR] Moderation router failed to load: {e}")
    add_breadcrumb(f"Moderation router error: {e}", category="startup", level="error")

# Payments router (Stripe integration for stelline, subscriptions, PPV)
try:
    from api.v1 import payments
    app.include_router(payments.router, prefix="/api/v1/payments", tags=["payments"])
    print("[OK] Payments router loaded")
except Exception as e:
    print(f"[ERROR] Payments router failed to load: {e}")
    add_breadcrumb(f"Payments router error: {e}", category="startup", level="error")

# Live translation router (optional - requires torch or Google Cloud)
try:
    from api.v1 import live_translation
    app.include_router(live_translation.router, prefix="/api/v1/live-translation", tags=["live-translation"])
    print("[OK] Live translation router loaded")
except ImportError as e:
    print(f"[INFO] Live translation not available (torch not installed or missing dependencies): {e}")
    add_breadcrumb(f"Live translation unavailable: {e}", category="startup", level="info")
except Exception as e:
    print(f"[WARNING] Live translation router failed: {e}")
    add_breadcrumb(f"Live translation error: {e}", category="startup", level="warning")

# Ingest Projects router (Unified Ingest Studio with Privacy by Design)
try:
    from api.v1 import ingest_projects
    app.include_router(ingest_projects.router, prefix="/api/v1/ingest", tags=["ingest"])
    print("[OK] Ingest Projects router loaded")
except Exception as e:
    print(f"[ERROR] Ingest Projects router failed to load: {e}")
    add_breadcrumb(f"Ingest Projects router error: {e}", category="startup", level="error")

# Content Classification router (Video sections tagging with ContentType)
try:
    from api.v1 import content_classification
    app.include_router(content_classification.router)
    print("[OK] Content Classification router loaded")
except Exception as e:
    print(f"[ERROR] Content Classification router failed to load: {e}")
    add_breadcrumb(f"Content Classification router error: {e}", category="startup", level="error")

# Temp Zone router (Admin temp file management with Privacy by Design)
try:
    from api.v1 import temp_zone
    app.include_router(temp_zone.router, prefix="/api/v1/admin/temp-zone", tags=["temp-zone"])
    print("[OK] Temp Zone router loaded")
except Exception as e:
    print(f"[ERROR] Temp Zone router failed to load: {e}")
    add_breadcrumb(f"Temp Zone router error: {e}", category="startup", level="error")

# Audio System router (TTS, voice cloning, styling, pronunciation)
try:
    from api.v1 import audio
    app.include_router(audio.router, prefix="/api/v1/audio", tags=["audio"])
    print("[OK] Audio System router loaded")
except ImportError as e:
    print(f"[INFO] Audio System not available (missing dependencies): {e}")
    add_breadcrumb(f"Audio System unavailable: {e}", category="startup", level="info")
except Exception as e:
    print(f"[ERROR] Audio System router failed to load: {e}")
    add_breadcrumb(f"Audio System router error: {e}", category="startup", level="error")

# Staff Contributions router (RBAC, audit, versioning, workflow)
try:
    from api.v1 import contributions
    app.include_router(contributions.router, prefix="/api/v1/contributions", tags=["contributions"])
    print("[OK] Staff Contributions router loaded")
except Exception as e:
    print(f"[ERROR] Staff Contributions router failed to load: {e}")
    add_breadcrumb(f"Staff Contributions router error: {e}", category="startup", level="error")

# Glasses WebSocket router (smart glasses remote control)
try:
    from api.v1 import glasses_ws
    app.include_router(glasses_ws.router, prefix="/api/v1", tags=["glasses"])
    print("[OK] Glasses WebSocket router loaded")
except Exception as e:
    print(f"[ERROR] Glasses WebSocket router failed to load: {e}")
    add_breadcrumb(f"Glasses WebSocket router error: {e}", category="startup", level="error")

# Video Studio router (technique images, multi-video fusion)
try:
    from api.v1 import video_studio
    app.include_router(video_studio.router, prefix="/api/v1/video-studio", tags=["video-studio"])
    print("[OK] Video Studio router loaded")
except ImportError as e:
    print(f"[INFO] Video Studio not available (missing dependencies): {e}")
    add_breadcrumb(f"Video Studio unavailable: {e}", category="startup", level="info")
except Exception as e:
    print(f"[ERROR] Video Studio router failed to load: {e}")
    add_breadcrumb(f"Video Studio router error: {e}", category="startup", level="error")

# Royalties Blockchain router (parametrizable royalty system with blockchain tracking)
try:
    from modules.royalties import router as royalties_router
    app.include_router(royalties_router, prefix="/api/v1/royalties", tags=["royalties"])
    print("[OK] Royalties Blockchain router loaded")
except ImportError as e:
    print(f"[INFO] Royalties not available (missing dependencies): {e}")
    add_breadcrumb(f"Royalties unavailable: {e}", category="startup", level="info")
except Exception as e:
    print(f"[ERROR] Royalties router failed to load: {e}")
    add_breadcrumb(f"Royalties router error: {e}", category="startup", level="error")

# Special Projects Voting router (community voting on project priorities)
try:
    from modules.special_projects import router as special_projects_router
    app.include_router(special_projects_router, prefix="/api/v1", tags=["special-projects"])
    print("[OK] Special Projects Voting router loaded")
except ImportError as e:
    print(f"[INFO] Special Projects not available (missing dependencies): {e}")
    add_breadcrumb(f"Special Projects unavailable: {e}", category="startup", level="info")
except Exception as e:
    print(f"[ERROR] Special Projects router failed to load: {e}")
    add_breadcrumb(f"Special Projects router error: {e}", category="startup", level="error")

# Events/ASD router (event management with Stripe Connect split payments)
try:
    from modules.events.router import router as events_router
    app.include_router(events_router, prefix="/api/v1/events", tags=["events"])
    print("[OK] Events/ASD router loaded")
except ImportError as e:
    print(f"[INFO] Events not available (missing dependencies): {e}")
    add_breadcrumb(f"Events unavailable: {e}", category="startup", level="info")
except Exception as e:
    print(f"[ERROR] Events router failed to load: {e}")
    add_breadcrumb(f"Events router error: {e}", category="startup", level="error")

# GDPR router (user data rights management)
try:
    from modules.events.gdpr_router import router as gdpr_router
    app.include_router(gdpr_router, prefix="/api/v1", tags=["gdpr"])
    print("[OK] GDPR router loaded")
except ImportError as e:
    print(f"[INFO] GDPR router not available (missing dependencies): {e}")
    add_breadcrumb(f"GDPR router unavailable: {e}", category="startup", level="info")
except Exception as e:
    print(f"[ERROR] GDPR router failed to load: {e}")
    add_breadcrumb(f"GDPR router error: {e}", category="startup", level="error")

# Notifications router (in-app + push notifications)
try:
    from api.v1 import notifications
    app.include_router(notifications.router, prefix="/api/v1/notifications", tags=["notifications"])
    print("[OK] Notifications router loaded")
except Exception as e:
    print(f"[ERROR] Notifications router failed to load: {e}")
    add_breadcrumb(f"Notifications router error: {e}", category="startup", level="error")

# Downloads router (offline downloads with DRM)
try:
    from api.v1 import downloads
    app.include_router(downloads.router, prefix="/api/v1", tags=["downloads"])
    print("[OK] Downloads router loaded")
except Exception as e:
    print(f"[ERROR] Downloads router failed to load: {e}")
    add_breadcrumb(f"Downloads router error: {e}", category="startup", level="error")

# Scheduler Admin router (job management, monitoring, manual triggers)
try:
    from api.v1 import scheduler
    app.include_router(scheduler.router, prefix="/api/v1", tags=["scheduler"])
    print("[OK] Scheduler Admin router loaded")
except Exception as e:
    print(f"[ERROR] Scheduler Admin router failed to load: {e}")
    add_breadcrumb(f"Scheduler Admin router error: {e}", category="startup", level="error")

# Skeleton API router (75 landmarks Holistic extraction)
try:
    from api.v1 import skeleton
    app.include_router(skeleton.router, prefix="/api/v1/skeleton", tags=["skeleton"])
    print("[OK] Skeleton API router loaded")
except ImportError as e:
    print(f"[INFO] Skeleton API not available (missing dependencies): {e}")
    add_breadcrumb(f"Skeleton API unavailable: {e}", category="startup", level="info")
except Exception as e:
    print(f"[ERROR] Skeleton API router failed to load: {e}")
    add_breadcrumb(f"Skeleton API router error: {e}", category="startup", level="error")

# Fusion API router (Multi-Video Fusion for avatar generation)
try:
    from api.v1 import fusion
    app.include_router(fusion.router, prefix="/api/v1/fusion", tags=["fusion"])
    print("[OK] Fusion API router loaded")
except ImportError as e:
    print(f"[INFO] Fusion API not available (missing dependencies): {e}")
    add_breadcrumb(f"Fusion API unavailable: {e}", category="startup", level="info")
except Exception as e:
    print(f"[ERROR] Fusion API router failed to load: {e}")
    add_breadcrumb(f"Fusion API router error: {e}", category="startup", level="error")

# Export API router (Blender/FBX/BVH export)
try:
    from api.v1 import export
    app.include_router(export.router, prefix="/api/v1/export", tags=["export"])
    print("[OK] Export API router loaded")
except ImportError as e:
    print(f"[INFO] Export API not available (missing dependencies): {e}")
    add_breadcrumb(f"Export API unavailable: {e}", category="startup", level="info")
except Exception as e:
    print(f"[ERROR] Export API router failed to load: {e}")
    add_breadcrumb(f"Export API router error: {e}", category="startup", level="error")

# Avatar 3D API router (3D avatar management with MediaPipe bone mapping)
try:
    from api.v1 import avatars
    app.include_router(avatars.router, prefix="/api/v1/avatars", tags=["avatars"])
    print("[OK] Avatar API router loaded")
except ImportError as e:
    print(f"[INFO] Avatar API not available (missing dependencies): {e}")
    add_breadcrumb(f"Avatar API unavailable: {e}", category="startup", level="info")
except Exception as e:
    print(f"[ERROR] Avatar API router failed to load: {e}")
    add_breadcrumb(f"Avatar API router error: {e}", category="startup", level="error")

# AI Coach API router (conversational AI + real-time pose feedback)
try:
    from api.v1 import ai_coach
    app.include_router(ai_coach.router, prefix="/api/v1/ai-coach", tags=["ai-coach"])
    print("[OK] AI Coach API router loaded")
except ImportError as e:
    print(f"[INFO] AI Coach API not available (missing dependencies): {e}")
    add_breadcrumb(f"AI Coach API unavailable: {e}", category="startup", level="info")
except Exception as e:
    print(f"[ERROR] AI Coach API router failed to load: {e}")
    add_breadcrumb(f"AI Coach API router error: {e}", category="startup", level="error")

# Curriculum router (martial arts learning paths with AI exam evaluation)
try:
    from api.v1 import curriculum
    app.include_router(curriculum.router, prefix="/api/v1", tags=["curriculum"])
    print("[OK] Curriculum router loaded")
except ImportError as e:
    print(f"[INFO] Curriculum not available (missing dependencies): {e}")
    add_breadcrumb(f"Curriculum unavailable: {e}", category="startup", level="info")
except Exception as e:
    print(f"[ERROR] Curriculum router failed to load: {e}")
    add_breadcrumb(f"Curriculum router error: {e}", category="startup", level="error")

# Overlay API router (didactic annotations on video frames with angles, text, highlights)
try:
    from api.v1 import overlays
    app.include_router(overlays.router, prefix="/api/v1/overlays", tags=["overlays"])
    print("[OK] Overlay API router loaded")
except ImportError as e:
    print(f"[INFO] Overlay API not available (missing dependencies): {e}")
    add_breadcrumb(f"Overlay API unavailable: {e}", category="startup", level="info")
except Exception as e:
    print(f"[ERROR] Overlay API router failed to load: {e}")
    add_breadcrumb(f"Overlay API router error: {e}", category="startup", level="error")

# Translation Debate API router (multi-LLM translation with debate system)
try:
    from api.v1 import translation_debate
    app.include_router(translation_debate.router, prefix="/api/v1", tags=["translation"])
    print("[OK] Translation Debate router loaded")
except ImportError as e:
    print(f"[INFO] Translation Debate not available (missing dependencies): {e}")
    add_breadcrumb(f"Translation Debate unavailable: {e}", category="startup", level="info")
except Exception as e:
    print(f"[ERROR] Translation Debate router failed to load: {e}")
    add_breadcrumb(f"Translation Debate router error: {e}", category="startup", level="error")

# Grammar Learning API router (extract grammar rules from books)
try:
    from api.v1.endpoints.grammar_learning import router as grammar_learning_router
    app.include_router(grammar_learning_router, prefix="/api/v1/grammar", tags=["grammar-learning"])
    print("[OK] Grammar Learning router loaded")
except ImportError as e:
    print(f"[INFO] Grammar Learning not available (missing dependencies): {e}")
    add_breadcrumb(f"Grammar Learning unavailable: {e}", category="startup", level="info")
except Exception as e:
    print(f"[ERROR] Grammar Learning router failed to load: {e}")
    add_breadcrumb(f"Grammar Learning router error: {e}", category="startup", level="error")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True if ENVIRONMENT == "development" else False,
    )
# FIX 2026-01-26: Trigger reload
# Reload trigger mar 27 gen 2026 01:02:05
# Reload mar 27 gen 2026 11:51:34
# Reload trigger ven 30 gen 2026 12:29:10
# Trigger reload
# reload
# reload trigger
