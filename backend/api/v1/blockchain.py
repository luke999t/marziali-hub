"""BLOCKCHAIN API ROUTER"""
import logging
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import datetime, timedelta
from typing import Optional

from core.database import get_db

logger = logging.getLogger(__name__)
from core.security import get_current_admin_user
from models.user import User
from modules.blockchain.blockchain_service import BlockchainService
from api.v1.schemas import MessageResponse

router = APIRouter()


@router.post("/batches/create")
async def create_weekly_batch(
    week_offset: int = 0,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(get_current_admin_user)
):
    """
    Create weekly batch for blockchain publication.

    Args:
        week_offset: 0 = current week, -1 = last week, -2 = 2 weeks ago, etc.
    """
    # Calculate week start/end
    now = datetime.utcnow()
    week_start = now - timedelta(days=now.weekday(), weeks=abs(week_offset))
    week_start = week_start.replace(hour=0, minute=0, second=0, microsecond=0)
    week_end = week_start + timedelta(days=7)

    service = BlockchainService(db)

    try:
        batch_id = await service.create_weekly_batch(week_start, week_end)

        return {
            "success": True,
            "batch_id": batch_id,
            "week_start": week_start.isoformat(),
            "week_end": week_end.isoformat(),
            "message": "Batch created successfully"
        }

    except Exception as e:
        import traceback
        traceback.print_exc()
        error_detail = f"{type(e).__name__}: {str(e)}"
        print(f"ERROR: Blockchain batch creation error: {error_detail}")
        raise HTTPException(status_code=500, detail=error_detail)


@router.post("/batches/{batch_id}/broadcast")
async def broadcast_batch(
    batch_id: str,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(get_current_admin_user)
):
    """Broadcast batch to store nodes for validation."""
    service = BlockchainService(db)

    try:
        result = await service.broadcast_batch_to_nodes(batch_id)
        return result

    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/batches/{batch_id}/validate")
async def receive_validation(
    batch_id: str,
    node_id: str,
    is_valid: bool,
    computed_hash: str,
    notes: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    """
    Receive validation from a store node.

    NOTE: In production questo endpoint dovrebbe essere protetto
    con firma digitale del nodo per evitare validazioni fake.
    """
    from sqlalchemy.exc import ProgrammingError
    import uuid

    # Validate UUID format
    try:
        uuid.UUID(batch_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid batch ID format")

    service = BlockchainService(db)

    try:
        result = await service.receive_node_validation(
            batch_id=batch_id,
            node_id=node_id,
            is_valid=is_valid,
            computed_hash=computed_hash,
            notes=notes
        )
        return result

    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except ProgrammingError as e:
        # Schema mismatch - treat as batch not found
        logger.error(f"Database schema error for batch {batch_id}: {e}")
        raise HTTPException(status_code=404, detail="Batch not found")
    except Exception as e:
        logger.error(f"Validation error for batch {batch_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/batches/{batch_id}/publish")
async def publish_batch(
    batch_id: str,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(get_current_admin_user)
):
    """
    Publish batch to Polygon blockchain after consensus.

    Requirements:
    - Consensus must be reached (>51% nodes validated)
    - Master wallet must be configured
    - Smart contract must be deployed
    """
    service = BlockchainService(db)

    try:
        result = await service.publish_to_blockchain(batch_id)
        return result

    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Blockchain error: {str(e)}")


@router.get("/batches/{batch_id}")
async def get_batch_status(
    batch_id: str,
    db: AsyncSession = Depends(get_db)
):
    """Get batch status and details."""
    from sqlalchemy import select
    from sqlalchemy.exc import ProgrammingError, DataError
    from models.ads import BlockchainBatch
    import uuid

    # Validate UUID format
    try:
        uuid.UUID(batch_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Invalid batch ID format")

    try:
        result = await db.execute(
            select(BlockchainBatch).where(BlockchainBatch.id == batch_id)
        )
        batch = result.scalar_one_or_none()
    except (ProgrammingError, DataError) as e:
        # Schema mismatch or invalid data - treat as not found
        logger.error(f"Database error querying batch {batch_id}: {e}")
        raise HTTPException(status_code=404, detail="Batch not found")

    if not batch:
        raise HTTPException(status_code=404, detail="Batch not found")

    consensus_status_value = batch.consensus_status.value if batch.consensus_status else None

    return {
        "batch_id": str(batch.id),
        "batch_date": batch.batch_date.isoformat() if batch.batch_date else None,
        "period_start": batch.period_start.isoformat() if batch.period_start else None,
        "period_end": batch.period_end.isoformat() if batch.period_end else None,
        "status": consensus_status_value,  # Alias for backward compatibility
        "consensus_status": consensus_status_value,
        "total_views": batch.total_views,
        "unique_users": batch.unique_users,
        "total_watch_time": batch.total_watch_time,
        "total_revenue": batch.total_revenue,
        "data_hash": batch.data_hash,
        "blockchain_tx_hash": batch.blockchain_tx_hash,
        "published_at": batch.published_at.isoformat() if batch.published_at else None,
        "explorer_url": f"https://polygonscan.com/tx/{batch.blockchain_tx_hash}" if batch.blockchain_tx_hash else None
    }
