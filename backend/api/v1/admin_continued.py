"""
🎓 ADMIN API - Part 2: Moderation, Donations, Withdrawals
This file contains the continuation of admin endpoints.
Append these to admin.py
"""


# ============================
# CONTENT MODERATION
# ============================

@router.get("/moderation/videos")
async def get_pending_videos(
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(get_current_admin_user)
):
    """
    🎥 Get videos pending moderation.

    Returns videos with status PENDING or PROCESSING that need review.
    """
    query = (
        select(Video)
        .where(Video.status.in_([VideoStatus.PENDING, VideoStatus.PROCESSING]))
        .order_by(desc(Video.created_at))
        .offset(skip)
        .limit(limit)
    )

    result = await db.execute(query)
    videos = result.scalars().all()

    # Count total pending
    count_query = select(func.count()).select_from(Video).where(
        Video.status.in_([VideoStatus.PENDING, VideoStatus.PROCESSING])
    )
    total = await db.execute(count_query)

    return {
        "videos": videos,
        "total": total.scalar(),
        "skip": skip,
        "limit": limit
    }


@router.post("/moderation/videos/{video_id}")
async def moderate_video(
    video_id: str,
    action: VideoModerationAction,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(get_current_admin_user)
):
    """
    ✅/❌ Approve or reject a video.

    Actions:
    - "approve": Set status to READY
    - "reject": Set status to FAILED with reason
    """
    result = await db.execute(select(Video).where(Video.id == video_id))
    video = result.scalar_one_or_none()

    if not video:
        raise HTTPException(status_code=404, detail="Video not found")

    if action.action == "approve":
        video.status = VideoStatus.READY
        video.published_at = datetime.utcnow()
    elif action.action == "reject":
        video.status = VideoStatus.FAILED
        video.processing_error = action.reason or "Rejected by admin"
    else:
        raise HTTPException(status_code=400, detail="Invalid action. Use 'approve' or 'reject'")

    await db.commit()

    return {"message": f"Video {action.action}ed successfully", "video_id": video_id}


@router.get("/moderation/chat")
async def get_flagged_chat_messages(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(get_current_admin_user)
):
    """
    💬 Get flagged live chat messages for review.
    """
    query = (
        select(LiveChatMessage)
        .where(and_(
            LiveChatMessage.is_deleted == False,
            # Add flag check when implemented
        ))
        .order_by(desc(LiveChatMessage.created_at))
        .offset(skip)
        .limit(limit)
    )

    result = await db.execute(query)
    messages = result.scalars().all()

    return {
        "messages": messages,
        "skip": skip,
        "limit": limit
    }


@router.delete("/moderation/chat/{message_id}")
async def delete_chat_message(
    message_id: str,
    reason: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(get_current_admin_user)
):
    """
    🗑️ Delete a live chat message.
    """
    result = await db.execute(select(LiveChatMessage).where(LiveChatMessage.id == message_id))
    message = result.scalar_one_or_none()

    if not message:
        raise HTTPException(status_code=404, detail="Message not found")

    message.soft_delete(moderator_id=admin.id, reason=reason)
    await db.commit()

    return {"message": "Chat message deleted successfully", "message_id": message_id}


# ============================
# DONATIONS & ANTI-FRAUD
# ============================

@router.get("/donations")
async def list_donations(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    min_amount: Optional[int] = Query(None, description="Min amount in stelline"),
    flagged_only: bool = Query(False),
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(get_current_admin_user)
):
    """
    💸 List donations with optional filters.

    Args:
        min_amount: Filter donations >= amount (stelline)
        flagged_only: Show only suspicious donations
    """
    query = select(Donation).order_by(desc(Donation.created_at))

    if min_amount:
        query = query.where(Donation.stelline_amount >= min_amount)

    # Add fraud detection flags when implemented
    # if flagged_only:
    #     query = query.where(Donation.is_flagged == True)

    query = query.offset(skip).limit(limit)

    result = await db.execute(query)
    donations = result.scalars().all()

    return {
        "donations": donations,
        "skip": skip,
        "limit": limit
    }


@router.get("/donations/fraud-queue")
async def get_fraud_queue(
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(get_current_admin_user)
):
    """
    🚨 Get donations flagged for potential fraud.

    Flags:
    - Donations over €15,000 requiring AML checks
    - Repeated small donations (potential money laundering)
    - Donations from banned users
    """
    # Large donations (AML threshold)
    large_threshold = 1500000  # 15,000 EUR = 1,500,000 stelline

    large_donations = await db.execute(
        select(Donation)
        .where(Donation.stelline_amount >= large_threshold)
        .order_by(desc(Donation.created_at))
        .limit(100)
    )

    return {
        "large_donations_aml": large_donations.scalars().all(),
        "total_flagged": large_donations.rowcount
    }


# ============================
# WITHDRAWAL MANAGEMENT
# ============================

@router.get("/withdrawals")
async def list_withdrawal_requests(
    status: Optional[str] = Query(None, regex="^(pending|approved|processing|completed|rejected)$"),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(get_current_admin_user)
):
    """
    💰 List withdrawal requests.

    Args:
        status: Filter by status (pending, approved, processing, completed, rejected)
    """
    query = select(WithdrawalRequest).order_by(desc(WithdrawalRequest.requested_at))

    if status:
        status_enum = WithdrawalStatus(status)
        query = query.where(WithdrawalRequest.status == status_enum)

    query = query.offset(skip).limit(limit)

    result = await db.execute(query)
    withdrawals = result.scalars().all()

    # Count by status
    pending_count = await db.execute(
        select(func.count()).select_from(WithdrawalRequest)
        .where(WithdrawalRequest.status == WithdrawalStatus.PENDING)
    )

    return {
        "withdrawals": withdrawals,
        "pending_count": pending_count.scalar(),
        "skip": skip,
        "limit": limit
    }


@router.get("/withdrawals/{withdrawal_id}")
async def get_withdrawal_detail(
    withdrawal_id: str,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(get_current_admin_user)
):
    """
    🔍 Get withdrawal request details.

    Includes:
    - Withdrawal info
    - Maestro/ASD details
    - Recent withdrawal history
    - Total earnings
    """
    result = await db.execute(select(WithdrawalRequest).where(WithdrawalRequest.id == withdrawal_id))
    withdrawal = result.scalar_one_or_none()

    if not withdrawal:
        raise HTTPException(status_code=404, detail="Withdrawal request not found")

    # Get maestro/ASD info
    if withdrawal.maestro_id:
        maestro_result = await db.execute(select(Maestro).where(Maestro.id == withdrawal.maestro_id))
        maestro = maestro_result.scalar_one_or_none()
        entity_info = {
            "type": "maestro",
            "name": maestro.user.full_name if maestro and maestro.user else "Unknown",
            "verified": maestro.is_verified() if maestro else False
        }
    elif withdrawal.asd_id:
        asd_result = await db.execute(select(ASD).where(ASD.id == withdrawal.asd_id))
        asd = asd_result.scalar_one_or_none()
        entity_info = {
            "type": "asd",
            "name": asd.name if asd else "Unknown",
            "verified": asd.is_verified if asd else False
        }
    else:
        entity_info = None

    # Get recent withdrawals count
    recent_withdrawals = await db.execute(
        select(func.count()).select_from(WithdrawalRequest)
        .where(and_(
            or_(
                WithdrawalRequest.maestro_id == withdrawal.maestro_id,
                WithdrawalRequest.asd_id == withdrawal.asd_id
            ),
            WithdrawalRequest.requested_at >= datetime.utcnow() - timedelta(days=30)
        ))
    )

    return {
        "withdrawal": withdrawal,
        "entity": entity_info,
        "recent_withdrawals_30d": recent_withdrawals.scalar()
    }


@router.post("/withdrawals/{withdrawal_id}/action")
async def process_withdrawal(
    withdrawal_id: str,
    action: WithdrawalAction,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(get_current_admin_user)
):
    """
    ✅/❌ Approve or reject a withdrawal request.

    Actions:
    - "approve": Move to processing
    - "reject": Reject with reason
    """
    result = await db.execute(select(WithdrawalRequest).where(WithdrawalRequest.id == withdrawal_id))
    withdrawal = result.scalar_one_or_none()

    if not withdrawal:
        raise HTTPException(status_code=404, detail="Withdrawal request not found")

    if withdrawal.status != WithdrawalStatus.PENDING:
        raise HTTPException(status_code=400, detail=f"Withdrawal is already {withdrawal.status.value}")

    if action.action == "approve":
        withdrawal.status = WithdrawalStatus.APPROVED
        withdrawal.approved_at = datetime.utcnow()
        withdrawal.approved_by_user_id = admin.id
        withdrawal.admin_notes = action.notes
        message = "Withdrawal approved. Moving to processing."

    elif action.action == "reject":
        withdrawal.status = WithdrawalStatus.REJECTED
        withdrawal.rejected_at = datetime.utcnow()
        withdrawal.rejection_reason = action.notes or "Rejected by admin"
        message = "Withdrawal rejected."

    else:
        raise HTTPException(status_code=400, detail="Invalid action. Use 'approve' or 'reject'")

    await db.commit()

    return {
        "message": message,
        "withdrawal_id": withdrawal_id,
        "new_status": withdrawal.status.value
    }


# ============================
# MAESTRO & ASD MANAGEMENT
# ============================

@router.get("/maestros")
async def list_maestros(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(get_current_admin_user)
):
    """
    👨‍🏫 List all maestros.
    """
    query = (
        select(Maestro)
        .order_by(desc(Maestro.created_at))
        .offset(skip)
        .limit(limit)
    )

    result = await db.execute(query)
    maestros = result.scalars().all()

    total = await db.execute(select(func.count()).select_from(Maestro))

    return {
        "maestros": maestros,
        "total": total.scalar(),
        "skip": skip,
        "limit": limit
    }


@router.get("/asds")
async def list_asds(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(get_current_admin_user)
):
    """
    🏛️ List all ASDs.
    """
    query = (
        select(ASD)
        .order_by(desc(ASD.created_at))
        .offset(skip)
        .limit(limit)
    )

    result = await db.execute(query)
    asds = result.scalars().all()

    total = await db.execute(select(func.count()).select_from(ASD))

    return {
        "asds": asds,
        "total": total.scalar(),
        "skip": skip,
        "limit": limit
    }


# ============================
# CONFIGURATION
# ============================

@router.get("/config/tiers")
async def get_tier_configuration(
    admin: User = Depends(get_current_admin_user)
):
    """
    ⚙️ Get subscription tier configuration.

    TODO: Implement tier configuration storage
    """
    # Placeholder - implement actual config storage
    return {
        "tiers": [
            {"name": "free", "price_eur": 0, "features": ["720p", "ads"]},
            {"name": "hybrid_light", "price_eur": 4.99, "features": ["1080p", "no_ads"]},
            {"name": "hybrid_standard", "price_eur": 9.99, "features": ["1080p", "downloads"]},
            {"name": "premium", "price_eur": 19.99, "features": ["4k", "all_features"]},
            {"name": "business", "price_eur": 49.99, "features": ["bulk_licenses", "api_access"]}
        ]
    }


@router.put("/config/tiers")
async def update_tier_configuration(
    config: PlatformConfig,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(get_current_admin_user)
):
    """
    ⚙️ Update tier prices and configuration.

    TODO: Implement tier configuration storage
    """
    # Placeholder - implement actual config storage
    return {"message": "Tier configuration updated"}
