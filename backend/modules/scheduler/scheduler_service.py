"""
AI_MODULE: Scheduler Service
AI_DESCRIPTION: APScheduler service for managing background maintenance jobs
AI_BUSINESS: Centralized job scheduling with monitoring, pause/resume, manual trigger
AI_TEACHING: APScheduler AsyncIOScheduler integration with FastAPI
AI_CREATED: 2025-01-17
AI_TASK: CODE 3 - Backend Scheduler Jobs & Maintenance System

FIX_2025_01_21: Corretto parametro add_listener (events -> mask) per APScheduler 3.x
"""

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Coroutine, Dict, List, Optional

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger
from apscheduler.jobstores.memory import MemoryJobStore
from apscheduler.executors.asyncio import AsyncIOExecutor
from apscheduler.events import EVENT_JOB_EXECUTED, EVENT_JOB_ERROR

logger = logging.getLogger(__name__)


class JobStatus(str, Enum):
    """
    AI_DESCRIPTION: Status enum for scheduled jobs
    """
    IDLE = "idle"
    RUNNING = "running"
    PAUSED = "paused"
    FAILED = "failed"
    SUCCESS = "success"


@dataclass
class JobResult:
    """
    AI_DESCRIPTION: Result of a job execution
    AI_TEACHING: Dataclass for structured job result reporting
    """
    job_id: str
    status: JobStatus
    started_at: datetime
    finished_at: Optional[datetime] = None
    records_processed: int = 0
    error_message: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)

    @property
    def duration_seconds(self) -> Optional[float]:
        """Calculate execution duration in seconds."""
        if self.finished_at and self.started_at:
            return (self.finished_at - self.started_at).total_seconds()
        return None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API responses."""
        return {
            "job_id": self.job_id,
            "status": self.status.value,
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "duration_seconds": self.duration_seconds,
            "records_processed": self.records_processed,
            "error_message": self.error_message,
            "details": self.details,
        }


@dataclass
class JobDefinition:
    """
    AI_DESCRIPTION: Definition of a scheduled job
    AI_TEACHING: Configuration dataclass for job registration
    """
    job_id: str
    name: str
    description: str
    func: Callable[..., Coroutine[Any, Any, JobResult]]
    trigger_type: str  # "cron" or "interval"
    trigger_args: Dict[str, Any]
    enabled: bool = True
    max_instances: int = 1
    coalesce: bool = True  # Combine missed runs into one
    misfire_grace_time: int = 60  # Seconds to allow late execution


# Singleton scheduler instance
_scheduler_instance: Optional["SchedulerService"] = None


def get_scheduler() -> "SchedulerService":
    """
    AI_DESCRIPTION: Get the singleton scheduler instance
    AI_TEACHING: Singleton pattern for global scheduler access
    """
    global _scheduler_instance
    if _scheduler_instance is None:
        _scheduler_instance = SchedulerService()
    return _scheduler_instance


class SchedulerService:
    """
    AI_DESCRIPTION: APScheduler service for managing background jobs
    AI_BUSINESS: Handles job lifecycle, monitoring, and manual triggers
    AI_TEACHING: Wraps APScheduler with additional tracking and control
    """

    def __init__(self):
        """Initialize the scheduler service."""
        # Configure job stores and executors
        jobstores = {
            "default": MemoryJobStore()
        }
        executors = {
            "default": AsyncIOExecutor()
        }
        job_defaults = {
            "coalesce": True,
            "max_instances": 1,
            "misfire_grace_time": 60,
        }

        self._scheduler = AsyncIOScheduler(
            jobstores=jobstores,
            executors=executors,
            job_defaults=job_defaults,
            timezone="Europe/Rome",
        )

        # Track job definitions and history
        self._job_definitions: Dict[str, JobDefinition] = {}
        self._job_history: Dict[str, List[JobResult]] = {}
        self._running_jobs: Dict[str, JobResult] = {}
        self._is_running = False

        # FIX_2025_01_21: APScheduler 3.x usa parametro 'mask', non 'events'
        # EVENT_JOB_EXECUTED e EVENT_JOB_ERROR importati da apscheduler.events
        self._scheduler.add_listener(
            self._on_job_executed,
            mask=EVENT_JOB_EXECUTED
        )
        self._scheduler.add_listener(
            self._on_job_error,
            mask=EVENT_JOB_ERROR
        )

        logger.info("SchedulerService initialized")

    @property
    def is_running(self) -> bool:
        """Check if scheduler is running."""
        return self._is_running

    def _on_job_executed(self, event):
        """Handle job execution success event."""
        job_id = event.job_id
        if job_id in self._running_jobs:
            result = self._running_jobs.pop(job_id)
            result.finished_at = datetime.now()
            result.status = JobStatus.SUCCESS
            self._add_to_history(job_id, result)
            logger.info(f"Job {job_id} completed successfully")

    def _on_job_error(self, event):
        """Handle job execution error event."""
        job_id = event.job_id
        if job_id in self._running_jobs:
            result = self._running_jobs.pop(job_id)
            result.finished_at = datetime.now()
            result.status = JobStatus.FAILED
            result.error_message = str(event.exception)
            self._add_to_history(job_id, result)
            logger.error(f"Job {job_id} failed: {event.exception}")

    def _add_to_history(self, job_id: str, result: JobResult):
        """Add job result to history, keeping last 100 entries per job."""
        if job_id not in self._job_history:
            self._job_history[job_id] = []
        self._job_history[job_id].append(result)
        # Keep only last 100 entries
        if len(self._job_history[job_id]) > 100:
            self._job_history[job_id] = self._job_history[job_id][-100:]

    def register_job(self, definition: JobDefinition) -> bool:
        """
        AI_DESCRIPTION: Register a new job with the scheduler
        AI_TEACHING: Creates APScheduler job from JobDefinition
        """
        try:
            # Create trigger based on type
            if definition.trigger_type == "cron":
                trigger = CronTrigger(**definition.trigger_args)
            elif definition.trigger_type == "interval":
                trigger = IntervalTrigger(**definition.trigger_args)
            else:
                logger.error(f"Unknown trigger type: {definition.trigger_type}")
                return False

            # Wrap the job function to track execution
            async def wrapped_job():
                result = JobResult(
                    job_id=definition.job_id,
                    status=JobStatus.RUNNING,
                    started_at=datetime.now(),
                )
                self._running_jobs[definition.job_id] = result

                try:
                    # Execute the actual job
                    job_result = await definition.func()

                    # Update result with job output
                    result.records_processed = job_result.records_processed
                    result.details = job_result.details
                    result.status = job_result.status
                    result.error_message = job_result.error_message

                except Exception as e:
                    result.status = JobStatus.FAILED
                    result.error_message = str(e)
                    logger.exception(f"Job {definition.job_id} failed with exception")

                finally:
                    result.finished_at = datetime.now()
                    if definition.job_id in self._running_jobs:
                        self._running_jobs.pop(definition.job_id)
                    self._add_to_history(definition.job_id, result)

                return result

            # Add job to scheduler
            self._scheduler.add_job(
                wrapped_job,
                trigger=trigger,
                id=definition.job_id,
                name=definition.name,
                max_instances=definition.max_instances,
                coalesce=definition.coalesce,
                misfire_grace_time=definition.misfire_grace_time,
                replace_existing=True,
            )

            # Store definition
            self._job_definitions[definition.job_id] = definition

            # Pause if not enabled
            if not definition.enabled:
                self._scheduler.pause_job(definition.job_id)

            logger.info(f"Registered job: {definition.job_id} ({definition.name})")
            return True

        except Exception as e:
            logger.exception(f"Failed to register job {definition.job_id}: {e}")
            return False

    def start(self):
        """
        AI_DESCRIPTION: Start the scheduler
        AI_TEACHING: Should be called during FastAPI startup
        """
        if not self._is_running:
            self._scheduler.start()
            self._is_running = True
            logger.info("Scheduler started")

    def shutdown(self, wait: bool = True):
        """
        AI_DESCRIPTION: Shutdown the scheduler gracefully
        AI_TEACHING: Should be called during FastAPI shutdown
        """
        if self._is_running:
            self._scheduler.shutdown(wait=wait)
            self._is_running = False
            logger.info("Scheduler shutdown")

    def pause_job(self, job_id: str) -> bool:
        """Pause a specific job."""
        try:
            self._scheduler.pause_job(job_id)
            logger.info(f"Paused job: {job_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to pause job {job_id}: {e}")
            return False

    def resume_job(self, job_id: str) -> bool:
        """Resume a paused job."""
        try:
            self._scheduler.resume_job(job_id)
            logger.info(f"Resumed job: {job_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to resume job {job_id}: {e}")
            return False

    def remove_job(self, job_id: str) -> bool:
        """Remove a job from the scheduler."""
        try:
            self._scheduler.remove_job(job_id)
            if job_id in self._job_definitions:
                del self._job_definitions[job_id]
            logger.info(f"Removed job: {job_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to remove job {job_id}: {e}")
            return False

    async def trigger_job(self, job_id: str) -> Optional[JobResult]:
        """
        AI_DESCRIPTION: Manually trigger a job immediately
        AI_TEACHING: Useful for admin manual execution
        """
        if job_id not in self._job_definitions:
            logger.error(f"Job not found: {job_id}")
            return None

        # Check if already running
        if job_id in self._running_jobs:
            logger.warning(f"Job {job_id} is already running")
            return self._running_jobs[job_id]

        definition = self._job_definitions[job_id]

        result = JobResult(
            job_id=job_id,
            status=JobStatus.RUNNING,
            started_at=datetime.now(),
        )
        self._running_jobs[job_id] = result

        try:
            # Execute the job function directly
            job_result = await definition.func()

            result.records_processed = job_result.records_processed
            result.details = job_result.details
            result.status = job_result.status
            result.error_message = job_result.error_message

        except Exception as e:
            result.status = JobStatus.FAILED
            result.error_message = str(e)
            logger.exception(f"Manual trigger of job {job_id} failed")

        finally:
            result.finished_at = datetime.now()
            if job_id in self._running_jobs:
                self._running_jobs.pop(job_id)
            self._add_to_history(job_id, result)

        return result

    def get_job_status(self, job_id: str) -> Optional[Dict[str, Any]]:
        """
        AI_DESCRIPTION: Get current status of a job
        AI_TEACHING: Returns job info including next run time
        """
        job = self._scheduler.get_job(job_id)
        if not job:
            return None

        definition = self._job_definitions.get(job_id)
        is_running = job_id in self._running_jobs

        # Get last result from history
        last_result = None
        if job_id in self._job_history and self._job_history[job_id]:
            last_result = self._job_history[job_id][-1].to_dict()

        return {
            "job_id": job_id,
            "name": job.name,
            "description": definition.description if definition else None,
            "trigger_type": definition.trigger_type if definition else None,
            "next_run_time": job.next_run_time.isoformat() if job.next_run_time else None,
            "is_paused": job.next_run_time is None,
            "is_running": is_running,
            "enabled": definition.enabled if definition else True,
            "last_result": last_result,
        }

    def get_all_jobs(self) -> List[Dict[str, Any]]:
        """
        AI_DESCRIPTION: Get status of all registered jobs
        AI_TEACHING: Returns list of all job statuses
        """
        jobs = []
        for job_id in self._job_definitions:
            status = self.get_job_status(job_id)
            if status:
                jobs.append(status)
        return jobs

    def get_job_history(
        self,
        job_id: str,
        limit: int = 10
    ) -> List[Dict[str, Any]]:
        """
        AI_DESCRIPTION: Get execution history for a job
        AI_TEACHING: Returns last N executions with results
        """
        if job_id not in self._job_history:
            return []

        history = self._job_history[job_id][-limit:]
        return [result.to_dict() for result in reversed(history)]

    def get_running_jobs(self) -> List[Dict[str, Any]]:
        """Get all currently running jobs."""
        return [result.to_dict() for result in self._running_jobs.values()]
