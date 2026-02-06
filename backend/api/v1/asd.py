"""
🎓 ASD API - Gestional Panel for Sports Associations
🎓 Endpoints: Dashboard, Maestros, Members, Events, Earnings, Reports
"""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, or_, desc
from typing import List, Optional
from datetime import datetime, timedelta
from pydantic import BaseModel

from core.database import get_db
from core.security import get_current_user
from models.user import User
from models.maestro import Maestro, ASD, ASDMember
from models.video import LiveEvent, LiveEventStatus, LiveEventType
from models.donation import Donation, WithdrawalRequest, WithdrawalStatus, PayoutMethod

router = APIRouter()


# ============================
# SCHEMAS
# ============================

class MemberCreate(BaseModel):
    user_id: str
    member_number: Optional[str] = None
    membership_fee: Optional[int] = None  # Euro cents
    fee_valid_until: Optional[datetime] = None


class EventCreate(BaseModel):
    title: str
    description: Optional[str] = None
    event_type: str  # LiveEventType
    maestro_id: str
    scheduled_start: datetime
    scheduled_end: Optional[datetime] = None
    fundraising_goal: Optional[int] = None


class WithdrawalCreateASD(BaseModel):
    stelline_amount: int
    payout_method: str  # PayoutMethod
    iban: Optional[str] = None
    paypal_email: Optional[str] = None


# ============================
# HELPERS
# ============================

async def get_current_asd(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
) -> tuple[ASD, User]:
    """Get current user's ASD or raise 403."""
    # TODO: Implement proper ASD admin relationship
    # For now, check if user has permission to manage specific ASD
    # This would typically check a ASDAdmin junction table

    # Placeholder: Get ASD from query param or user association
    # In production, implement proper authorization
    raise HTTPException(
        status_code=501,
        detail="ASD authorization not yet implemented. TODO: Add ASDAdmin relationship table."
    )


async def get_asd_by_id(asd_id: str, db: AsyncSession) -> ASD:
    """Helper to get ASD by ID."""
    import uuid

    # FIX: Validate UUID format before querying database
    try:
        uuid.UUID(asd_id)
    except (ValueError, AttributeError):
        raise HTTPException(status_code=404, detail="ASD not found")

    result = await db.execute(select(ASD).where(ASD.id == asd_id))
    asd = result.scalar_one_or_none()

    if not asd:
        raise HTTPException(status_code=404, detail="ASD not found")

    return asd


# ============================
# DASHBOARD
# ============================

@router.get("/{asd_id}/dashboard")
async def get_asd_dashboard(
    asd_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    📊 ASD dashboard with key metrics.

    Returns:
    - Total maestros, members
    - Earnings (last 30 days)
    - Upcoming events
    - Membership status
    """
    asd = await get_asd_by_id(asd_id, db)

    # Count affiliated maestros
    maestros_count = await db.execute(
        select(func.count()).select_from(Maestro).where(Maestro.asd_id == asd_id)
    )

    # Count active members
    active_members = await db.execute(
        select(func.count()).select_from(ASDMember).where(and_(
            ASDMember.asd_id == asd_id,
            ASDMember.status == "active"
        ))
    )

    # Earnings last 30 days
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)
    donations_30d = await db.execute(
        select(
            func.count(Donation.id),
            func.sum(Donation.stelline_amount)
        ).where(and_(
            Donation.to_asd_id == asd_id,
            Donation.created_at >= thirty_days_ago
        ))
    )
    donation_stats = donations_30d.one()

    # Upcoming events
    upcoming_events = await db.execute(
        select(func.count()).select_from(LiveEvent).where(and_(
            LiveEvent.asd_id == asd_id,
            LiveEvent.status == LiveEventStatus.SCHEDULED,
            LiveEvent.scheduled_start > datetime.utcnow()
        ))
    )

    return {
        "asd": {
            "id": asd.id,
            "name": asd.name,
            "codice_fiscale": asd.codice_fiscale,
            "is_verified": asd.is_verified
        },
        "total_maestros": maestros_count.scalar(),
        "total_members": asd.total_members,
        "active_members": active_members.scalar(),
        "earnings_last_30_days": {
            "donations_count": donation_stats[0] or 0,
            "stelline": donation_stats[1] or 0,
            "eur": round((donation_stats[1] or 0) * 0.01, 2)
        },
        "upcoming_events": upcoming_events.scalar()
    }


# ============================
# MAESTRO MANAGEMENT
# ============================

@router.get("/{asd_id}/maestros")
async def list_asd_maestros(
    asd_id: str,
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    👨‍🏫 List ASD affiliated maestros.
    """
    asd = await get_asd_by_id(asd_id, db)

    query = (
        select(Maestro)
        .where(Maestro.asd_id == asd_id)
        .order_by(desc(Maestro.created_at))
        .offset(skip)
        .limit(limit)
    )

    result = await db.execute(query)
    maestros = result.scalars().all()

    return {
        "maestros": maestros,
        "total": asd.total_maestros,
        "skip": skip,
        "limit": limit
    }


# ============================
# MEMBER MANAGEMENT
# ============================

@router.get("/{asd_id}/members")
async def list_members(
    asd_id: str,
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    status: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    👥 List ASD members.

    Args:
        status: Filter by status (active, suspended, expired)
    """
    asd = await get_asd_by_id(asd_id, db)

    query = select(ASDMember).where(ASDMember.asd_id == asd_id)

    if status:
        query = query.where(ASDMember.status == status)

    query = query.order_by(desc(ASDMember.joined_at)).offset(skip).limit(limit)

    result = await db.execute(query)
    members = result.scalars().all()

    return {
        "members": members,
        "skip": skip,
        "limit": limit
    }


@router.post("/{asd_id}/members")
async def add_member(
    asd_id: str,
    data: MemberCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    ➕ Add a new member to ASD.
    """
    asd = await get_asd_by_id(asd_id, db)

    # Check if user exists
    user_result = await db.execute(select(User).where(User.id == data.user_id))
    user = user_result.scalar_one_or_none()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Check if already a member
    existing = await db.execute(
        select(ASDMember).where(and_(
            ASDMember.asd_id == asd_id,
            ASDMember.user_id == data.user_id
        ))
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="User is already a member")

    member = ASDMember(
        asd_id=asd_id,
        user_id=data.user_id,
        member_number=data.member_number,
        membership_fee=data.membership_fee,
        fee_valid_until=data.fee_valid_until,
        status="active"
    )

    db.add(member)
    asd.total_members += 1
    await db.commit()
    await db.refresh(member)

    return {"message": "Member added successfully", "member": member}


@router.get("/{asd_id}/members/{member_id}")
async def get_member_detail(
    asd_id: str,
    member_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    🔍 Get member details.

    Includes:
    - Member info
    - Payment history
    - Medical certificate status
    - Activity history
    """
    asd = await get_asd_by_id(asd_id, db)

    result = await db.execute(
        select(ASDMember).where(and_(
            ASDMember.id == member_id,
            ASDMember.asd_id == asd_id
        ))
    )
    member = result.scalar_one_or_none()

    if not member:
        raise HTTPException(status_code=404, detail="Member not found")

    # Check membership validity
    is_valid = member.is_membership_valid()
    needs_medical = member.needs_medical_certificate_renewal()

    return {
        "member": member,
        "is_membership_valid": is_valid,
        "needs_medical_certificate_renewal": needs_medical
    }


# ============================
# EVENTS & FUNDRAISING
# ============================

@router.get("/{asd_id}/events")
async def list_asd_events(
    asd_id: str,
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    upcoming_only: bool = Query(False),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    📅 List ASD events.
    """
    asd = await get_asd_by_id(asd_id, db)

    query = select(LiveEvent).where(LiveEvent.asd_id == asd_id).order_by(desc(LiveEvent.scheduled_start))

    if upcoming_only:
        query = query.where(and_(
            LiveEvent.status == LiveEventStatus.SCHEDULED,
            LiveEvent.scheduled_start > datetime.utcnow()
        ))

    query = query.offset(skip).limit(limit)

    result = await db.execute(query)
    events = result.scalars().all()

    return {
        "events": events,
        "skip": skip,
        "limit": limit
    }


@router.post("/{asd_id}/events")
async def create_asd_event(
    asd_id: str,
    data: EventCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    📡 Create ASD-organized event.

    Must specify maestro who will conduct the event.
    """
    import uuid

    asd = await get_asd_by_id(asd_id, db)

    # Verify maestro is affiliated with this ASD
    maestro_result = await db.execute(
        select(Maestro).where(and_(
            Maestro.id == data.maestro_id,
            Maestro.asd_id == asd_id
        ))
    )
    maestro = maestro_result.scalar_one_or_none()

    if not maestro:
        raise HTTPException(status_code=404, detail="Maestro not affiliated with this ASD")

    stream_key = f"asd_{asd_id}_{uuid.uuid4().hex[:12]}"

    event = LiveEvent(
        maestro_id=maestro.id,
        asd_id=asd_id,
        title=data.title,
        description=data.description,
        event_type=LiveEventType(data.event_type),
        scheduled_start=data.scheduled_start,
        scheduled_end=data.scheduled_end,
        stream_key=stream_key,
        rtmp_url=f"rtmp://live.platform.com/live/{stream_key}",
        donations_enabled=True,
        fundraising_goal=data.fundraising_goal
    )

    db.add(event)
    await db.commit()
    await db.refresh(event)

    return {"message": "Event created", "event": event}


# ============================
# EARNINGS & WITHDRAWALS
# ============================

@router.get("/{asd_id}/earnings")
async def get_asd_earnings(
    asd_id: str,
    period: str = Query("30d", regex="^(7d|30d|90d|365d|all)$"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    💰 Get ASD earnings from donations.
    """
    asd = await get_asd_by_id(asd_id, db)

    query = select(
        func.count(Donation.id),
        func.sum(Donation.stelline_amount)
    ).where(Donation.to_asd_id == asd_id)

    if period != "all":
        days_map = {"7d": 7, "30d": 30, "90d": 90, "365d": 365}
        start_date = datetime.utcnow() - timedelta(days=days_map[period])
        query = query.where(Donation.created_at >= start_date)

    result = await db.execute(query)
    stats = result.one()

    return {
        "period": period,
        "donations_count": stats[0] or 0,
        "total_stelline": stats[1] or 0,
        "total_eur": round((stats[1] or 0) * 0.01, 2)
    }


@router.post("/{asd_id}/withdrawals")
async def request_asd_withdrawal(
    asd_id: str,
    data: WithdrawalCreateASD,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    💸 Request withdrawal for ASD.

    Minimum: 10,000 stelline (€100)
    """
    MIN_WITHDRAWAL = 1000000  # 10,000 stelline = €100

    asd = await get_asd_by_id(asd_id, db)

    if data.stelline_amount < MIN_WITHDRAWAL:
        raise HTTPException(
            status_code=400,
            detail=f"Minimum withdrawal is {MIN_WITHDRAWAL} stelline (€{MIN_WITHDRAWAL * 0.01})"
        )

    euro_amount = data.stelline_amount * 0.01

    withdrawal = WithdrawalRequest(
        user_id=current_user.id,  # User requesting on behalf of ASD
        asd_id=asd_id,
        stelline_amount=data.stelline_amount,
        euro_amount=euro_amount,
        payout_method=PayoutMethod(data.payout_method),
        iban=data.iban,
        paypal_email=data.paypal_email,
        status=WithdrawalStatus.PENDING
    )

    db.add(withdrawal)
    await db.commit()
    await db.refresh(withdrawal)

    return {"message": "Withdrawal request submitted", "withdrawal": withdrawal}


@router.get("/{asd_id}/withdrawals")
async def list_asd_withdrawals(
    asd_id: str,
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    💸 List ASD withdrawal requests.
    """
    asd = await get_asd_by_id(asd_id, db)

    query = (
        select(WithdrawalRequest)
        .where(WithdrawalRequest.asd_id == asd_id)
        .order_by(desc(WithdrawalRequest.requested_at))
        .offset(skip)
        .limit(limit)
    )

    result = await db.execute(query)
    withdrawals = result.scalars().all()

    return {
        "withdrawals": withdrawals,
        "skip": skip,
        "limit": limit
    }


# ============================
# REPORTS & ACCOUNTING
# ============================

@router.get("/{asd_id}/reports/fiscal")
async def generate_fiscal_report(
    asd_id: str,
    year: int = Query(..., ge=2020, le=2100),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    📄 Generate fiscal year report for ASD.

    Italian non-profit compliance:
    - Total donations received
    - Breakdown by donor type (anonymous vs with CF)
    - Total withdrawals
    - Member fees collected
    """
    asd = await get_asd_by_id(asd_id, db)

    # Start and end of fiscal year
    start_date = datetime(year, 1, 1)
    end_date = datetime(year, 12, 31, 23, 59, 59)

    # Total donations
    donations_query = await db.execute(
        select(
            func.count(Donation.id),
            func.sum(Donation.stelline_amount),
            func.count(func.distinct(Donation.donor_codice_fiscale))
        ).where(and_(
            Donation.to_asd_id == asd_id,
            Donation.created_at >= start_date,
            Donation.created_at <= end_date
        ))
    )
    donation_stats = donations_query.one()

    # Anonymous vs identified donations
    anonymous_donations = await db.execute(
        select(
            func.count(Donation.id),
            func.sum(Donation.stelline_amount)
        ).where(and_(
            Donation.to_asd_id == asd_id,
            Donation.created_at >= start_date,
            Donation.created_at <= end_date,
            Donation.donor_codice_fiscale.is_(None)
        ))
    )
    anon_stats = anonymous_donations.one()

    # Total withdrawals
    withdrawals_query = await db.execute(
        select(
            func.count(WithdrawalRequest.id),
            func.sum(WithdrawalRequest.euro_amount)
        ).where(and_(
            WithdrawalRequest.asd_id == asd_id,
            WithdrawalRequest.completed_at >= start_date,
            WithdrawalRequest.completed_at <= end_date,
            WithdrawalRequest.status == WithdrawalStatus.COMPLETED
        ))
    )
    withdrawal_stats = withdrawals_query.one()

    return {
        "asd": {
            "name": asd.name,
            "codice_fiscale": asd.codice_fiscale,
            "presidente": asd.presidente_name
        },
        "fiscal_year": year,
        "donations": {
            "total_count": donation_stats[0] or 0,
            "total_stelline": donation_stats[1] or 0,
            "total_eur": round((donation_stats[1] or 0) * 0.01, 2),
            "unique_donors": donation_stats[2] or 0,
            "anonymous_count": anon_stats[0] or 0,
            "anonymous_eur": round((anon_stats[1] or 0) * 0.01, 2),
            "identified_count": (donation_stats[0] or 0) - (anon_stats[0] or 0)
        },
        "withdrawals": {
            "count": withdrawal_stats[0] or 0,
            "total_eur": float(withdrawal_stats[1] or 0)
        },
        "net_balance_eur": round((donation_stats[1] or 0) * 0.01 - float(withdrawal_stats[1] or 0), 2)
    }
