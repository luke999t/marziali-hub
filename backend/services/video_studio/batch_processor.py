"""
Batch Video Processing System
Handles multiple video uploads and parallel processing with progress tracking
"""

from typing import List, Dict, Optional, Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import asyncio
import uuid
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


class BatchStatus(str, Enum):
    """Batch processing status"""
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class VideoProcessingStatus(str, Enum):
    """Individual video processing status"""
    QUEUED = "queued"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class VideoJob:
    """Individual video processing job"""
    video_id: str
    filename: str
    filepath: str
    status: VideoProcessingStatus = VideoProcessingStatus.QUEUED
    progress: int = 0
    error: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    result: Optional[Dict] = None

    def to_dict(self) -> Dict:
        return {
            "video_id": self.video_id,
            "filename": self.filename,
            "status": self.status.value,
            "progress": self.progress,
            "error": self.error,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "result": self.result
        }


@dataclass
class BatchJob:
    """Batch processing job containing multiple videos"""
    batch_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    project_id: Optional[str] = None
    videos: List[VideoJob] = field(default_factory=list)
    status: BatchStatus = BatchStatus.PENDING
    created_at: datetime = field(default_factory=datetime.utcnow)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    max_parallel: int = 3  # Maximum parallel video processing
    total_videos: int = 0
    completed_count: int = 0
    failed_count: int = 0
    progress_callback: Optional[Callable] = None

    def __post_init__(self):
        self.total_videos = len(self.videos)

    def get_progress(self) -> int:
        """Calculate overall batch progress percentage"""
        if not self.videos:
            return 0

        total_progress = sum(video.progress for video in self.videos)
        return int(total_progress / self.total_videos) if self.total_videos > 0 else 0

    def get_status_summary(self) -> Dict:
        """Get summary of video statuses"""
        summary = {
            "queued": 0,
            "processing": 0,
            "completed": 0,
            "failed": 0,
            "skipped": 0
        }

        for video in self.videos:
            summary[video.status.value] += 1

        return summary

    def to_dict(self) -> Dict:
        """Convert batch job to dictionary"""
        return {
            "batch_id": self.batch_id,
            "project_id": self.project_id,
            "status": self.status.value,
            "progress": self.get_progress(),
            "total_videos": self.total_videos,
            "completed_count": self.completed_count,
            "failed_count": self.failed_count,
            "status_summary": self.get_status_summary(),
            "created_at": self.created_at.isoformat(),
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "videos": [video.to_dict() for video in self.videos]
        }


class BatchProcessor:
    """Manages batch video processing operations"""

    def __init__(self):
        self.active_batches: Dict[str, BatchJob] = {}
        self.batch_history: List[Dict] = []
        self.max_batch_history = 100

    def create_batch(self, video_files: List[Dict], project_id: Optional[str] = None, max_parallel: int = 3) -> BatchJob:
        """
        Create a new batch processing job

        Args:
            video_files: List of video file info dicts with 'filename' and 'filepath'
            project_id: Optional project ID to associate with
            max_parallel: Maximum number of videos to process in parallel

        Returns:
            BatchJob instance
        """
        video_jobs = []
        for video_info in video_files:
            video_job = VideoJob(
                video_id=str(uuid.uuid4()),
                filename=video_info['filename'],
                filepath=video_info['filepath']
            )
            video_jobs.append(video_job)

        batch = BatchJob(
            project_id=project_id,
            videos=video_jobs,
            max_parallel=max_parallel
        )

        self.active_batches[batch.batch_id] = batch
        logger.info(f"Created batch {batch.batch_id} with {len(video_jobs)} videos")

        return batch

    async def process_batch(self, batch_id: str, processing_func: Callable) -> BatchJob:
        """
        Process a batch of videos

        Args:
            batch_id: ID of the batch to process
            processing_func: Async function to process individual videos
                           Should accept (video_id, filepath) and return result dict

        Returns:
            Completed BatchJob
        """
        batch = self.active_batches.get(batch_id)
        if not batch:
            raise ValueError(f"Batch {batch_id} not found")

        batch.status = BatchStatus.PROCESSING
        batch.started_at = datetime.utcnow()

        logger.info(f"Starting batch processing for {batch_id} with {len(batch.videos)} videos")

        # Process videos in parallel batches
        semaphore = asyncio.Semaphore(batch.max_parallel)

        async def process_video_with_semaphore(video: VideoJob):
            async with semaphore:
                return await self._process_single_video(video, processing_func, batch)

        # Create tasks for all videos
        tasks = [process_video_with_semaphore(video) for video in batch.videos]

        # Wait for all to complete
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Update batch status
        batch.status = BatchStatus.COMPLETED
        batch.completed_at = datetime.utcnow()

        # Count completions and failures
        batch.completed_count = sum(1 for v in batch.videos if v.status == VideoProcessingStatus.COMPLETED)
        batch.failed_count = sum(1 for v in batch.videos if v.status == VideoProcessingStatus.FAILED)

        logger.info(f"Batch {batch_id} completed: {batch.completed_count} successful, {batch.failed_count} failed")

        # Move to history
        self._archive_batch(batch)

        return batch

    async def _process_single_video(self, video: VideoJob, processing_func: Callable, batch: BatchJob) -> Dict:
        """Process a single video with error handling"""
        try:
            video.status = VideoProcessingStatus.PROCESSING
            video.started_at = datetime.utcnow()
            logger.info(f"Processing video {video.video_id}: {video.filename}")

            # Call the processing function with progress callback
            async def update_progress(progress: int):
                video.progress = progress
                if batch.progress_callback:
                    await batch.progress_callback(batch.to_dict())

            result = await processing_func(video.video_id, video.filepath, update_progress)

            video.status = VideoProcessingStatus.COMPLETED
            video.progress = 100
            video.result = result
            video.completed_at = datetime.utcnow()

            logger.info(f"Video {video.video_id} processed successfully")
            return result

        except Exception as e:
            logger.error(f"Error processing video {video.video_id}: {str(e)}")
            video.status = VideoProcessingStatus.FAILED
            video.error = str(e)
            video.completed_at = datetime.utcnow()
            raise

    def get_batch_status(self, batch_id: str) -> Optional[Dict]:
        """Get current status of a batch"""
        batch = self.active_batches.get(batch_id)
        if batch:
            return batch.to_dict()

        # Check history
        for historical_batch in self.batch_history:
            if historical_batch['batch_id'] == batch_id:
                return historical_batch

        return None

    def cancel_batch(self, batch_id: str) -> bool:
        """Cancel a batch processing job"""
        batch = self.active_batches.get(batch_id)
        if not batch:
            return False

        if batch.status == BatchStatus.PROCESSING:
            batch.status = BatchStatus.CANCELLED
            logger.info(f"Batch {batch_id} cancelled")
            self._archive_batch(batch)
            return True

        return False

    def _archive_batch(self, batch: BatchJob):
        """Move completed batch to history"""
        self.batch_history.insert(0, batch.to_dict())
        if len(self.batch_history) > self.max_batch_history:
            self.batch_history.pop()

        if batch.batch_id in self.active_batches:
            del self.active_batches[batch.batch_id]

    def get_active_batches(self) -> List[Dict]:
        """Get all currently active batches"""
        return [batch.to_dict() for batch in self.active_batches.values()]

    def get_batch_history(self, limit: int = 20) -> List[Dict]:
        """Get batch processing history"""
        return self.batch_history[:limit]

    def get_statistics(self) -> Dict:
        """Get overall batch processing statistics"""
        total_batches = len(self.active_batches) + len(self.batch_history)
        total_videos_processed = sum(
            batch.get('completed_count', 0) + batch.get('failed_count', 0)
            for batch in self.batch_history
        )

        return {
            "active_batches": len(self.active_batches),
            "total_batches_processed": len(self.batch_history),
            "total_videos_processed": total_videos_processed,
            "current_active_videos": sum(
                sum(1 for v in batch.videos if v.status == VideoProcessingStatus.PROCESSING)
                for batch in self.active_batches.values()
            )
        }


# Global batch processor instance
batch_processor = BatchProcessor()
