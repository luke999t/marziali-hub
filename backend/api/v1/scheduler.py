"""
================================================================================
AI_MODULE: Scheduler Admin API
AI_VERSION: 1.0.0
AI_DESCRIPTION: Admin endpoints per gestione e monitoring job scheduler
AI_BUSINESS: Monitoring job, trigger manuale, pause/resume, storico esecuzioni
AI_TEACHING: REST API for APScheduler management

ENDPOINT_DISPONIBILI:
- GET /scheduler/jobs - Lista tutti i job con stato
- GET /scheduler/jobs/{job_id} - Dettaglio singolo job
- GET /scheduler/jobs/{job_id}/history - Storico esecuzioni
- POST /scheduler/jobs/{job_id}/trigger - Trigger manuale immediato
- POST /scheduler/jobs/{job_id}/pause - Pausa job
- POST /scheduler/jobs/{job_id}/resume - Riprendi job
- GET /scheduler/running - Job in esecuzione
- GET /scheduler/health - Health status servizi
- GET /scheduler/backups - Lista backup disponibili
================================================================================
"""

from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from core.security import get_current_admin_user, get_current_user
from models.user import User
from modules.scheduler.scheduler_service import get_scheduler
from modules.scheduler.jobs.health_check import get_health_status
from modules.scheduler.jobs.database_backup import get_backup_list

router = APIRouter(prefix="/scheduler", tags=["Scheduler Admin"])


# ================================================================================
# SCHEMAS
# ================================================================================

class JobStatusResponse(BaseModel):
    job_id: str
    name: str
    description: Optional[str]
    trigger_type: Optional[str]
    next_run_time: Optional[str]
    is_paused: bool
    is_running: bool
    enabled: bool
    last_result: Optional[dict]


class JobHistoryItem(BaseModel):
    job_id: str
    status: str
    started_at: str
    finished_at: Optional[str]
    duration_seconds: Optional[float]
    records_processed: int
    error_message: Optional[str]
    details: dict


class TriggerResponse(BaseModel):
    success: bool
    job_id: str
    status: str
    message: str
    result: Optional[dict]


class HealthResponse(BaseModel):
    status: str
    services: dict
    system: dict
    checked_at: Optional[str]


class BackupInfo(BaseModel):
    filename: str
    path: str
    size_bytes: int
    size_mb: float
    created_at: str


# ================================================================================
# JOB MANAGEMENT ENDPOINTS
# ================================================================================

@router.get("/jobs", response_model=List[JobStatusResponse])
async def list_all_jobs(
    admin: User = Depends(get_current_admin_user)
):
    """
    📋 Lista tutti i job registrati con il loro stato attuale.

    Returns:
    - Lista di tutti i job con next_run_time, stato, ultimo risultato
    """
    scheduler = get_scheduler()
    jobs = scheduler.get_all_jobs()
    return jobs


@router.get("/jobs/{job_id}", response_model=JobStatusResponse)
async def get_job_details(
    job_id: str,
    current_user: User = Depends(get_current_user)
):
    """
    🔍 Dettaglio singolo job.

    Args:
        job_id: ID del job (es. "health_check", "daily_analytics")

    Returns:
        Dettagli completi del job incluso ultimo risultato
    """
    scheduler = get_scheduler()
    job_status = scheduler.get_job_status(job_id)

    if not job_status:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Job '{job_id}' not found"
        )

    return job_status


@router.get("/jobs/{job_id}/history", response_model=List[JobHistoryItem])
async def get_job_history(
    job_id: str,
    limit: int = 10,
    admin: User = Depends(get_current_admin_user)
):
    """
    📜 Storico esecuzioni di un job.

    Args:
        job_id: ID del job
        limit: Numero massimo di risultati (default 10, max 100)

    Returns:
        Lista ultime esecuzioni con dettagli risultato
    """
    scheduler = get_scheduler()

    # Verify job exists
    if scheduler.get_job_status(job_id) is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Job '{job_id}' not found"
        )

    # Limit to max 100
    limit = min(limit, 100)

    history = scheduler.get_job_history(job_id, limit=limit)
    return history


@router.post("/jobs/{job_id}/trigger", response_model=TriggerResponse)
async def trigger_job_manually(
    job_id: str,
    admin: User = Depends(get_current_admin_user)
):
    """
    ⚡ Trigger manuale immediato di un job.

    Args:
        job_id: ID del job da eseguire

    Returns:
        Risultato dell'esecuzione
    """
    scheduler = get_scheduler()

    # Verify job exists
    job_status = scheduler.get_job_status(job_id)
    if not job_status:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Job '{job_id}' not found"
        )

    # Check if already running
    if job_status.get("is_running"):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Job '{job_id}' is already running"
        )

    # Trigger the job
    result = await scheduler.trigger_job(job_id)

    if result is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to trigger job '{job_id}'"
        )

    return TriggerResponse(
        success=result.status.value in ["success", "running"],
        job_id=job_id,
        status=result.status.value,
        message=f"Job {job_id} triggered successfully",
        result=result.to_dict(),
    )


@router.post("/jobs/{job_id}/pause")
async def pause_job(
    job_id: str,
    admin: User = Depends(get_current_admin_user)
):
    """
    ⏸️ Metti in pausa un job.

    Args:
        job_id: ID del job da pausare

    Il job non verrà più eseguito automaticamente finché non viene ripreso.
    """
    scheduler = get_scheduler()

    # Verify job exists
    if scheduler.get_job_status(job_id) is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Job '{job_id}' not found"
        )

    success = scheduler.pause_job(job_id)

    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to pause job '{job_id}'"
        )

    return {
        "success": True,
        "job_id": job_id,
        "message": f"Job '{job_id}' paused",
        "timestamp": datetime.utcnow().isoformat()
    }


@router.post("/jobs/{job_id}/resume")
async def resume_job(
    job_id: str,
    admin: User = Depends(get_current_admin_user)
):
    """
    ▶️ Riprendi un job in pausa.

    Args:
        job_id: ID del job da riprendere
    """
    scheduler = get_scheduler()

    # Verify job exists
    if scheduler.get_job_status(job_id) is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Job '{job_id}' not found"
        )

    success = scheduler.resume_job(job_id)

    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to resume job '{job_id}'"
        )

    return {
        "success": True,
        "job_id": job_id,
        "message": f"Job '{job_id}' resumed",
        "timestamp": datetime.utcnow().isoformat()
    }


# ================================================================================
# MONITORING ENDPOINTS
# ================================================================================

@router.get("/running")
async def get_running_jobs(
    admin: User = Depends(get_current_admin_user)
):
    """
    🏃 Lista job attualmente in esecuzione.

    Returns:
        Lista di job running con dettagli esecuzione
    """
    scheduler = get_scheduler()
    running = scheduler.get_running_jobs()

    return {
        "count": len(running),
        "jobs": running,
        "timestamp": datetime.utcnow().isoformat()
    }


@router.get("/health", response_model=HealthResponse)
async def get_system_health(
    admin: User = Depends(get_current_admin_user)
):
    """
    🏥 Stato salute servizi (PostgreSQL, Redis, Storage).

    Returns:
        Stato ultimo health check con latenze e metriche sistema
    """
    health = get_health_status()
    return health


@router.get("/backups", response_model=List[BackupInfo])
async def list_backups(
    admin: User = Depends(get_current_admin_user)
):
    """
    💾 Lista backup database disponibili.

    Returns:
        Lista file backup con dimensioni e date
    """
    backups = get_backup_list()
    return backups


@router.get("/stats")
async def get_scheduler_stats(
    admin: User = Depends(get_current_admin_user)
):
    """
    📊 Statistiche aggregate dello scheduler.

    Returns:
        Conteggi job, successi, fallimenti, uptime
    """
    scheduler = get_scheduler()
    all_jobs = scheduler.get_all_jobs()

    # Count stats
    total_jobs = len(all_jobs)
    paused_jobs = sum(1 for j in all_jobs if j.get("is_paused"))
    running_jobs = sum(1 for j in all_jobs if j.get("is_running"))

    # Count success/failure from last results
    success_count = 0
    failure_count = 0

    for job in all_jobs:
        last_result = job.get("last_result")
        if last_result:
            if last_result.get("status") == "success":
                success_count += 1
            elif last_result.get("status") == "failed":
                failure_count += 1

    return {
        "total_jobs": total_jobs,
        "active_jobs": total_jobs - paused_jobs,
        "paused_jobs": paused_jobs,
        "running_jobs": running_jobs,
        "last_run_success": success_count,
        "last_run_failed": failure_count,
        "scheduler_running": scheduler.is_running,
        "timestamp": datetime.utcnow().isoformat()
    }
