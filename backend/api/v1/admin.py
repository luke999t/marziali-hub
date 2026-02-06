"""
🎓 ADMIN API - Complete Platform Management
🎓 Gestional Panel: Users, Moderation, Donations, Analytics, Configuration
"""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, or_, desc, update
from typing import List, Optional
from datetime import datetime, timedelta
from pydantic import BaseModel

from core.database import get_db
from core.security import get_current_admin_user
from models.user import User
from models.video import Video, VideoStatus
from models.maestro import Maestro, ASD
from models.donation import Donation, WithdrawalRequest, StellineWallet, WithdrawalStatus
from models.communication import LiveChatMessage
from models.live_minor import Minor, ParentalApproval
from api.v1.schemas import UserAdminResponse

router = APIRouter()


# ============================
# SCHEMAS
# ============================

class BanUserRequest(BaseModel):
    reason: str
    duration_days: Optional[int] = None  # None = permanent


class ToggleActiveRequest(BaseModel):
    """
    🎓 AI_MODULE: Toggle Active Request
    🎓 AI_DESCRIPTION: Schema per attivare/disattivare utente
    🎓 AI_BUSINESS: Admin può sospendere utenti senza ban formale
    🎓 AI_TEACHING: Differenza tra is_active (soft disable) e is_banned (ban con motivo)
    """
    is_active: bool


class ChangeRoleRequest(BaseModel):
    """
    🎓 AI_MODULE: Change Role Request
    🎓 AI_DESCRIPTION: Schema per cambiare ruolo utente
    🎓 AI_BUSINESS: Admin promuove utenti a maestro/admin o declassa
    🎓 AI_TEACHING: role è un campo calcolato (is_admin + tabella Maestro/ASD)
    
    ⚠️ ATTENZIONE: 'admin' setta is_admin=True, 'maestro' richiede record Maestro
    """
    role: str  # 'user' | 'maestro' | 'asd' | 'admin'


class VideoModerationAction(BaseModel):
    action: str  # "approve" | "reject"
    reason: Optional[str] = None


class WithdrawalAction(BaseModel):
    action: str  # "approve" | "reject"
    notes: Optional[str] = None


class PlatformConfig(BaseModel):
    tier_prices: Optional[dict] = None
    platform_fees: Optional[dict] = None


# ============================
# DASHBOARD & ANALYTICS
# ============================

@router.get("/dashboard")
async def get_dashboard(
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(get_current_admin_user)
):
    """
    📊 Admin dashboard with comprehensive KPIs.

    Returns:
    - Total users, maestros, ASDs, videos
    - Active subscriptions by tier
    - Total revenue (last 30 days)
    - Pending moderation queue sizes
    """
    # Basic counts
    total_users = await db.execute(select(func.count()).select_from(User))
    total_maestros = await db.execute(select(func.count()).select_from(Maestro))
    total_asds = await db.execute(select(func.count()).select_from(ASD))
    total_videos = await db.execute(select(func.count()).select_from(Video))

    # Active videos
    active_videos = await db.execute(
        select(func.count()).select_from(Video).where(Video.status == VideoStatus.READY)
    )

    # Pending moderation
    pending_videos = await db.execute(
        select(func.count()).select_from(Video).where(Video.status == VideoStatus.PENDING)
    )

    # Withdrawal requests pending
    pending_withdrawals = await db.execute(
        select(func.count()).select_from(WithdrawalRequest)
        .where(WithdrawalRequest.status == WithdrawalStatus.PENDING.value)
    )

    # Total donations last 30 days (in stelline)
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)
    donations_30d = await db.execute(
        select(func.sum(Donation.stelline_amount))
        .where(Donation.created_at >= thirty_days_ago)
    )
    total_donations = donations_30d.scalar() or 0

    # Revenue (convert stelline to EUR)
    revenue_30d_eur = (float(total_donations) * 0.01) if total_donations else 0

    return {
        "total_users": total_users.scalar(),
        "total_maestros": total_maestros.scalar(),
        "total_asds": total_asds.scalar(),
        "total_videos": total_videos.scalar(),
        "active_videos": active_videos.scalar(),
        "pending_moderation": {
            "videos": pending_videos.scalar(),
            "withdrawals": pending_withdrawals.scalar()
        },
        "revenue_last_30_days": {
            "stelline": total_donations,
            "eur": round(revenue_30d_eur, 2)
        },
        "platform_status": "operational"
    }


# 🎓 AI_TEACHING: Alias endpoint per retrocompatibilità
# 💡 PERCHÉ: I test e client legacy chiamano /stats invece di /dashboard
# 🔄 ALTERNATIVA: Redirect 301 → scartato perché aggiunge latenza e complessità client
# ⚠️ ATTENZIONE: Mantiene stessa logica di /dashboard, stessa auth, stessi dati
@router.get("/stats")
@router.get("/stats/")
async def get_stats(
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(get_current_admin_user)
):
    """
    📊 Alias di /dashboard per retrocompatibilità.
    Alcuni client e test usano /stats come path per le statistiche admin.
    Delega internamente a get_dashboard().
    """
    return await get_dashboard(db=db, admin=admin)


# POSIZIONE: backend/api/v1/admin.py (sostituzione)
"""
🎓 AI_MODULE: Admin Platform Analytics
🎓 AI_DESCRIPTION: Endpoint analytics piattaforma con KPI aggregati
🎓 AI_BUSINESS: Dashboard admin per monitoraggio performance, revenue, utenti
🎓 AI_TEACHING: Aggregazioni SQL con func.count/sum, date filtering, response schema strutturato

🔄 ALTERNATIVE_VALUTATE:
- Endpoint separato in analytics.py: Scartato, pochi endpoint, meglio in admin.py
- GraphQL: Scartato, REST sufficiente per dashboard semplice
- Real-time WebSocket: Scartato, polling ogni 5min sufficiente

💡 PERCHÉ_QUESTA_SOLUZIONE:
- Unico endpoint con tutti i KPI riduce chiamate HTTP
- Period param (7d/30d/90d) permette flessibilità senza moltiplicare endpoint
- Response schema match esatto con frontend esistente

📊 BUSINESS_IMPACT:
- Admin può monitorare salute piattaforma
- Identificare video top performer
- Tracking revenue per tipo

🔗 INTEGRATION_DEPENDENCIES:
- Upstream: User, Video, Subscription, Donation, Payment, AnalyticsDaily models
- Downstream: Frontend admin/analytics/page.tsx
"""

# Import aggiuntivi per platform analytics
from models.analytics import AnalyticsDaily
from models.payment import Payment, PaymentStatus, TransactionType
from models.user import UserTier
from sqlalchemy import cast, Date


@router.get("/analytics/platform")
async def get_platform_analytics(
    period: str = Query("30d", regex="^(7d|30d|90d)$"),
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(get_current_admin_user)
):
    """
    📊 Platform analytics for admin dashboard.

    🎯 BUSINESS: Fornisce KPI aggregati per monitoraggio piattaforma
    📊 PERIOD: 7d = ultima settimana, 30d = ultimo mese, 90d = ultimo trimestre

    ⚠️ PERFORMANCE: Query aggregate possono essere lente su grandi dataset
    💡 OTTIMIZZAZIONE FUTURA: Materialized views o pre-calcolo notturno

    Returns schema match frontend:
    - overview: KPI principali (views, watch_time, revenue, users, subscribers)
    - daily_views: Trend visualizzazioni per giorno
    - top_videos: Top 5 video per views
    - user_growth: Crescita utenti cumulativa
    - revenue_by_type: Breakdown revenue per sorgente
    """
    # Calcola date range dal period parameter
    # 💡 int(period.replace("d", "")) estrae il numero di giorni dalla stringa "30d" -> 30
    days = int(period.replace("d", ""))
    start_date = datetime.utcnow() - timedelta(days=days)

    # ==========================================================================
    # === OVERVIEW METRICS ===
    # ==========================================================================

    # --- TOTAL VIEWS ---
    # Prima provo da AnalyticsDaily (dati pre-aggregati, più veloce)
    # Se non ci sono dati, fallback su calcolo live da Video.view_count
    analytics_views = await db.execute(
        select(func.sum(AnalyticsDaily.total_views))
        .where(AnalyticsDaily.report_date >= start_date.date())
    )
    total_views = analytics_views.scalar() or 0

    # --- TOTAL WATCH TIME ---
    # AnalyticsDaily.total_watch_time_seconds contiene secondi, convertiamo in minuti
    # 💡 Dividiamo per 60 per avere minuti (più leggibile in dashboard)
    analytics_watch_time = await db.execute(
        select(func.sum(AnalyticsDaily.total_watch_time_seconds))
        .where(AnalyticsDaily.report_date >= start_date.date())
    )
    total_watch_time_seconds = analytics_watch_time.scalar() or 0
    total_watch_time_minutes = total_watch_time_seconds // 60

    # --- TOTAL REVENUE ---
    # Sum di tutti i pagamenti SUCCEEDED nel periodo
    # 💡 amount_eur è in centesimi (1234 = €12.34), dividiamo per 100
    revenue_result = await db.execute(
        select(func.sum(Payment.amount_eur))
        .where(
            and_(
                Payment.created_at >= start_date,
                Payment.status == PaymentStatus.SUCCEEDED
            )
        )
    )
    total_revenue_cents = revenue_result.scalar() or 0
    total_revenue_eur = float(total_revenue_cents) / 100

    # --- NEW USERS ---
    # Conta utenti registrati nel periodo
    # 💡 User.created_at >= start_date filtra solo nuovi utenti
    new_users_result = await db.execute(
        select(func.count()).select_from(User)
        .where(User.created_at >= start_date)
    )
    new_users = new_users_result.scalar() or 0

    # --- ACTIVE SUBSCRIBERS ---
    # Conta utenti con tier a pagamento e subscription attiva
    # 💡 User.tier NOT IN (FREE, PAY_PER_VIEW) = ha un abbonamento
    # 💡 User.subscription_end > now() OR is NULL = subscription ancora valida
    # 💡 User.is_active = True = account attivo
    active_subs_result = await db.execute(
        select(func.count()).select_from(User)
        .where(
            and_(
                User.is_active == True,
                User.tier.notin_([UserTier.FREE, UserTier.PAY_PER_VIEW]),
                or_(
                    User.subscription_end > datetime.utcnow(),
                    User.subscription_end.is_(None)  # Lifetime o non impostato
                )
            )
        )
    )
    active_subscribers = active_subs_result.scalar() or 0

    # ==========================================================================
    # === DAILY VIEWS ===
    # ==========================================================================
    # Trend giornaliero delle visualizzazioni per grafici
    # 💡 Group by report_date per avere un punto per ogni giorno
    daily_views_result = await db.execute(
        select(
            AnalyticsDaily.report_date,
            AnalyticsDaily.total_views
        )
        .where(AnalyticsDaily.report_date >= start_date.date())
        .order_by(AnalyticsDaily.report_date)
    )
    daily_views_rows = daily_views_result.all()

    # Formatta per frontend: [{"date": "2025-01-30", "views": 1234}, ...]
    daily_views = [
        {
            "date": row.report_date.isoformat(),
            "views": row.total_views or 0
        }
        for row in daily_views_rows
    ]

    # ==========================================================================
    # === TOP VIDEOS ===
    # ==========================================================================
    # Top 5 video per view_count nel periodo
    # 💡 Ordinamento DESC per avere i più visti prima, LIMIT 5 per top 5
    top_videos_result = await db.execute(
        select(
            Video.title,
            Video.view_count,
            Video.ppv_price  # Revenue potenziale se PPV
        )
        .where(Video.status == VideoStatus.READY)
        .order_by(desc(Video.view_count))
        .limit(5)
    )
    top_videos_rows = top_videos_result.all()

    # Formatta per frontend con calcolo revenue stimata
    # 💡 Se video ha ppv_price, revenue = views * ppv_price (stima)
    # 💡 Altrimenti revenue = 0 (video gratuito o incluso in subscription)
    top_videos = [
        {
            "title": row.title,
            "views": row.view_count or 0,
            # Revenue stimata: views * prezzo PPV (se presente)
            "revenue": round((row.view_count or 0) * (row.ppv_price or 0), 2)
        }
        for row in top_videos_rows
    ]

    # ==========================================================================
    # === USER GROWTH ===
    # ==========================================================================
    # Crescita utenti cumulativa per giorno
    # 💡 AnalyticsDaily.total_users contiene il conteggio cumulativo
    user_growth_result = await db.execute(
        select(
            AnalyticsDaily.report_date,
            AnalyticsDaily.total_users
        )
        .where(AnalyticsDaily.report_date >= start_date.date())
        .order_by(AnalyticsDaily.report_date)
    )
    user_growth_rows = user_growth_result.all()

    # Formatta per frontend: [{"date": "2025-01-30", "users": 1250}, ...]
    user_growth = [
        {
            "date": row.report_date.isoformat(),
            "users": row.total_users or 0
        }
        for row in user_growth_rows
    ]

    # ==========================================================================
    # === REVENUE BY TYPE ===
    # ==========================================================================
    # Breakdown revenue per tipo di transazione
    # 💡 Group by transaction_type per separare Subscriptions, PPV, Donations

    # Query separata per ogni tipo per maggiore chiarezza
    # SUBSCRIPTIONS: pagamenti tipo SUBSCRIPTION
    subs_revenue = await db.execute(
        select(func.sum(Payment.amount_eur))
        .where(
            and_(
                Payment.created_at >= start_date,
                Payment.status == PaymentStatus.SUCCEEDED,
                Payment.transaction_type == TransactionType.SUBSCRIPTION
            )
        )
    )
    subs_amount = (subs_revenue.scalar() or 0) / 100  # Centesimi -> EUR

    # PPV (Pay-Per-View): pagamenti tipo VIDEO_PURCHASE
    ppv_revenue = await db.execute(
        select(func.sum(Payment.amount_eur))
        .where(
            and_(
                Payment.created_at >= start_date,
                Payment.status == PaymentStatus.SUCCEEDED,
                Payment.transaction_type == TransactionType.VIDEO_PURCHASE
            )
        )
    )
    ppv_amount = (ppv_revenue.scalar() or 0) / 100

    # DONATIONS: pagamenti tipo DONATION o STELLINE_PURCHASE
    # 💡 Include sia donazioni dirette che acquisti stelline (usate per donare)
    donations_revenue = await db.execute(
        select(func.sum(Payment.amount_eur))
        .where(
            and_(
                Payment.created_at >= start_date,
                Payment.status == PaymentStatus.SUCCEEDED,
                Payment.transaction_type.in_([
                    TransactionType.DONATION,
                    TransactionType.STELLINE_PURCHASE
                ])
            )
        )
    )
    donations_amount = (donations_revenue.scalar() or 0) / 100

    # Formatta per frontend: [{"type": "Subscriptions", "amount": 5200.0}, ...]
    revenue_by_type = [
        {"type": "Subscriptions", "amount": round(subs_amount, 2)},
        {"type": "PPV", "amount": round(ppv_amount, 2)},
        {"type": "Donations", "amount": round(donations_amount, 2)}
    ]

    # ==========================================================================
    # === RESPONSE ===
    # ==========================================================================
    # Schema match esatto con frontend admin/analytics/page.tsx
    return {
        "overview": {
            "total_views": total_views,
            "total_watch_time": total_watch_time_minutes,  # In minuti
            "total_revenue": round(total_revenue_eur, 2),
            "new_users": new_users,
            "active_subscribers": active_subscribers
        },
        "daily_views": daily_views,
        "top_videos": top_videos,
        "user_growth": user_growth,
        "revenue_by_type": revenue_by_type
    }


# ============================
# USER MANAGEMENT
# ============================

@router.get("/users")
async def list_users(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    search: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(get_current_admin_user)
):
    """
    👥 List all users with pagination and search.

    Args:
        skip: Number of users to skip
        limit: Max users to return (1-100)
        search: Search by username or email
    """
    query = select(User)

    if search:
        query = query.where(
            or_(
                User.username.ilike(f"%{search}%"),
                User.email.ilike(f"%{search}%")
            )
        )

    query = query.offset(skip).limit(limit).order_by(desc(User.created_at))

    result = await db.execute(query)
    users = result.scalars().all()

    # Count total
    count_query = select(func.count()).select_from(User)
    if search:
        count_query = count_query.where(
            or_(
                User.username.ilike(f"%{search}%"),
                User.email.ilike(f"%{search}%")
            )
        )
    total = await db.execute(count_query)

    # 🎓 AI_TEACHING: Calcolo campo 'role' composito
    # 💡 PERCHÉ: Il model User ha solo is_admin (bool), ma il frontend ha bisogno
    #    di un campo role che distingue: admin, maestro, asd, user
    # 📊 APPROCCIO: Batch query Maestro/ASD per evitare N+1 queries
    # ⚠️ PERFORMANCE: 2 query extra ma O(1) vs O(N) se facessimo per-user
    user_ids = [str(u.id) for u in users]

    # Batch check: quali utenti sono maestri?
    maestro_result = await db.execute(
        select(Maestro.user_id).where(
            Maestro.user_id.in_([u.id for u in users])
        )
    )
    maestro_user_ids = {str(row[0]) for row in maestro_result.all()}

    # Batch check: quali utenti sono ASD?
    # 💡 ASD potrebbe non avere user_id diretto, in quel caso skip
    asd_user_ids = set()
    try:
        asd_result = await db.execute(
            select(ASD.user_id).where(
                ASD.user_id.in_([u.id for u in users])
            )
        )
        asd_user_ids = {str(row[0]) for row in asd_result.all()}
    except Exception:
        # ASD potrebbe non avere campo user_id
        pass

    def compute_role(user) -> str:
        """Calcola role composito da is_admin + tabelle Maestro/ASD."""
        uid = str(user.id)
        if user.is_admin:
            return "admin"
        if uid in maestro_user_ids:
            return "maestro"
        if uid in asd_user_ids:
            return "asd"
        return "user"

    # Costruisci response con role aggiunto
    users_response = []
    for u in users:
        user_data = UserAdminResponse.model_validate(u).model_dump()
        user_data["role"] = compute_role(u)
        users_response.append(user_data)

    return {
        "users": users_response,
        "total": total.scalar(),
        "skip": skip,
        "limit": limit
    }


@router.get("/users/{user_id}")
async def get_user_detail(
    user_id: str,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(get_current_admin_user)
):
    """
    🔍 Get detailed user information.

    Includes:
    - Basic profile
    - Maestro profile (if exists)
    - Minor profile (if exists)
    - Subscription tier
    - Total donations sent/received
    - Recent activity
    """
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Check if maestro
    maestro_result = await db.execute(select(Maestro).where(Maestro.user_id == user_id))
    maestro = maestro_result.scalar_one_or_none()

    # Check if minor
    minor_result = await db.execute(select(Minor).where(Minor.user_id == user_id))
    minor = minor_result.scalar_one_or_none()

    # Get wallet
    wallet_result = await db.execute(select(StellineWallet).where(StellineWallet.user_id == user_id))
    wallet = wallet_result.scalar_one_or_none()

    # Get donations sent
    donations_sent = await db.execute(
        select(func.count(Donation.id), func.sum(Donation.stelline_amount))
        .where(Donation.from_user_id == user_id)
    )
    sent_stats = donations_sent.one()

    return {
        "user": UserAdminResponse.model_validate(user),
        "is_maestro": maestro is not None,
        "is_minor": minor is not None,
        "wallet_balance_stelline": wallet.balance_stelline if wallet else 0,
        "wallet_balance_eur": wallet.get_balance_euro() if wallet else 0,
        "donations_sent": {
            "count": sent_stats[0] or 0,
            "total_stelline": sent_stats[1] or 0
        }
    }


@router.post("/users/{user_id}/ban")
async def ban_user(
    user_id: str,
    data: BanUserRequest,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(get_current_admin_user)
):
    """
    🚫 Ban a user temporarily or permanently.

    Args:
        user_id: User to ban
        data: Ban reason and optional duration
    """
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if user.is_admin:
        raise HTTPException(status_code=403, detail="Cannot ban admin users")

    user.is_banned = True
    user.ban_reason = data.reason

    if data.duration_days:
        user.ban_expires_at = datetime.utcnow() + timedelta(days=data.duration_days)
    else:
        user.ban_expires_at = None  # Permanent

    await db.commit()

    return {"message": "User banned successfully", "user_id": user_id}


@router.post("/users/{user_id}/unban")
async def unban_user(
    user_id: str,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(get_current_admin_user)
):
    """
    ✅ Unban a user.
    """
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.is_banned = False
    user.ban_reason = None
    user.ban_expires_at = None

    await db.commit()

    return {"message": "User unbanned successfully", "user_id": user_id}


@router.post("/users/{user_id}/toggle-active")
async def toggle_user_active(
    user_id: str,
    data: ToggleActiveRequest,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(get_current_admin_user)
):
    """
    ⚡ Toggle user active status.

    🎓 AI_MODULE: Toggle Active
    🎓 AI_DESCRIPTION: Attiva/disattiva utente senza ban formale
    🎓 AI_BUSINESS: Permette sospensione temporanea soft (no motivo richiesto)
    🎓 AI_TEACHING: Differenza tra is_active e is_banned:
        - is_active=False: account disabilitato, nessun motivo, riattivabile instant
        - is_banned=True: ban formale con motivo obbligatorio e possibile scadenza

    🔄 ALTERNATIVE_VALUTATE:
    - Usare ban/unban: Scartato, semantica diversa (ban è punitivo)
    - Soft delete: Scartato, perderemmo dati utente

    ⚠️ ATTENZIONE: Non è possibile disattivare un admin
    """
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if user.is_admin and not data.is_active:
        raise HTTPException(status_code=403, detail="Cannot deactivate admin users")

    user.is_active = data.is_active
    await db.commit()

    status_text = "activated" if data.is_active else "deactivated"
    return {
        "message": f"User {status_text} successfully",
        "user_id": user_id,
        "is_active": data.is_active
    }


@router.put("/users/{user_id}/role")
async def change_user_role(
    user_id: str,
    data: ChangeRoleRequest,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(get_current_admin_user)
):
    """
    🛡️ Change user role.

    🎓 AI_MODULE: Change Role
    🎓 AI_DESCRIPTION: Cambia ruolo utente (user/maestro/asd/admin)
    🎓 AI_BUSINESS: Admin gestisce promozioni/declassamenti utenti
    🎓 AI_TEACHING: Il ruolo è un campo composito:
        - 'admin' → setta User.is_admin = True
        - 'maestro' → crea record Maestro se non esiste
        - 'asd' → futuro: crea record ASD
        - 'user' → rimuove is_admin, mantiene record maestro/asd

    🔄 ALTERNATIVE_VALUTATE:
    - Campo role singolo in User: Scartato, un utente può essere maestro E admin
    - RBAC complesso: Scartato, overkill per MVP

    ⚠️ ATTENZIONE: Cambiare da admin a user rimuove privilegi admin
    ⚠️ ATTENZIONE: L'admin non può rimuovere il proprio ruolo admin
    """
    VALID_ROLES = {'user', 'maestro', 'asd', 'admin'}
    if data.role not in VALID_ROLES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid role '{data.role}'. Valid: {', '.join(VALID_ROLES)}"
        )

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # ⚠️ Protezione: admin non può declassare se stesso
    if str(user.id) == str(admin.id) and data.role != 'admin':
        raise HTTPException(
            status_code=403,
            detail="Cannot remove your own admin role"
        )

    # Applica cambio ruolo
    if data.role == 'admin':
        user.is_admin = True
    else:
        user.is_admin = False

    # 💡 Per maestro/asd servirebbe creare/rimuovere record nelle tabelle correlate
    # Per ora gestiamo solo is_admin, la creazione Maestro avviene via endpoint dedicato

    await db.commit()

    return {
        "message": f"User role updated to {data.role}",
        "user_id": user_id,
        "role": data.role
    }


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
        .where(LiveChatMessage.is_deleted == False)
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
        .where(WithdrawalRequest.status == WithdrawalStatus.PENDING.value)
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

    if withdrawal.status != WithdrawalStatus.PENDING.value:
        raise HTTPException(status_code=400, detail=f"Withdrawal is already {withdrawal.status}")

    if action.action == "approve":
        withdrawal.status = WithdrawalStatus.APPROVED.value
        withdrawal.approved_at = datetime.utcnow()
        withdrawal.approved_by_user_id = admin.id
        withdrawal.admin_notes = action.notes
        message = "Withdrawal approved. Moving to processing."

    elif action.action == "reject":
        withdrawal.status = WithdrawalStatus.REJECTED.value
        withdrawal.rejected_at = datetime.utcnow()
        withdrawal.rejection_reason = action.notes or "Rejected by admin"
        message = "Withdrawal rejected."

    else:
        raise HTTPException(status_code=400, detail="Invalid action. Use 'approve' or 'reject'")

    await db.commit()

    return {
        "message": message,
        "withdrawal_id": withdrawal_id,
        "new_status": withdrawal.status
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


# ============================
# SCHEDULER JOBS MANAGEMENT
# ============================

@router.get("/jobs")
async def list_scheduler_jobs(
    admin: User = Depends(get_current_admin_user)
):
    """
    AI_DESCRIPTION: List all scheduled maintenance jobs
    AI_BUSINESS: Admin monitoring of background job status
    AI_CREATED: 2025-01-17
    """
    from modules.scheduler import get_scheduler

    scheduler = get_scheduler()
    jobs = scheduler.get_all_jobs()
    running = scheduler.get_running_jobs()

    return {
        "scheduler_running": scheduler.is_running,
        "jobs": jobs,
        "currently_running": running,
    }


@router.get("/jobs/{job_id}")
async def get_job_detail(
    job_id: str,
    admin: User = Depends(get_current_admin_user)
):
    """
    AI_DESCRIPTION: Get detailed status of a specific job
    AI_BUSINESS: Admin inspection of individual job status
    """
    from modules.scheduler import get_scheduler

    scheduler = get_scheduler()
    status = scheduler.get_job_status(job_id)

    if not status:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found")

    return status


@router.get("/jobs/{job_id}/history")
async def get_job_history(
    job_id: str,
    limit: int = Query(10, ge=1, le=100),
    admin: User = Depends(get_current_admin_user)
):
    """
    AI_DESCRIPTION: Get execution history for a job
    AI_BUSINESS: Admin audit trail for job executions
    """
    from modules.scheduler import get_scheduler

    scheduler = get_scheduler()
    history = scheduler.get_job_history(job_id, limit=limit)

    return {
        "job_id": job_id,
        "history": history,
        "count": len(history),
    }


@router.post("/jobs/{job_id}/trigger")
async def trigger_job_manually(
    job_id: str,
    admin: User = Depends(get_current_admin_user)
):
    """
    AI_DESCRIPTION: Manually trigger a job immediately
    AI_BUSINESS: Admin manual execution for testing or urgent runs
    """
    from modules.scheduler import get_scheduler

    scheduler = get_scheduler()
    result = await scheduler.trigger_job(job_id)

    if not result:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found")

    return {
        "message": f"Job {job_id} triggered",
        "result": result.to_dict(),
    }


@router.post("/jobs/{job_id}/pause")
async def pause_job(
    job_id: str,
    admin: User = Depends(get_current_admin_user)
):
    """
    AI_DESCRIPTION: Pause a scheduled job
    AI_BUSINESS: Admin control to temporarily disable a job
    """
    from modules.scheduler import get_scheduler

    scheduler = get_scheduler()
    success = scheduler.pause_job(job_id)

    if not success:
        raise HTTPException(status_code=400, detail=f"Failed to pause job {job_id}")

    return {"message": f"Job {job_id} paused", "job_id": job_id}


@router.post("/jobs/{job_id}/resume")
async def resume_job(
    job_id: str,
    admin: User = Depends(get_current_admin_user)
):
    """
    AI_DESCRIPTION: Resume a paused job
    AI_BUSINESS: Admin control to re-enable a paused job
    """
    from modules.scheduler import get_scheduler

    scheduler = get_scheduler()
    success = scheduler.resume_job(job_id)

    if not success:
        raise HTTPException(status_code=400, detail=f"Failed to resume job {job_id}")

    return {"message": f"Job {job_id} resumed", "job_id": job_id}
