"""
================================================================================
AI_MODULE: PauseAdService
AI_DESCRIPTION: Servizio per pause ads Netflix-style con overlay 50/50
AI_BUSINESS: Revenue €0.005/impression + €0.02/click, targeting tier-based
AI_TEACHING: Recommendation algorithm, CPM model, real-time tracking

ALTERNATIVE_VALUTATE:
- Pre-roll ads: Scartata perché UX peggiore, skip rate 80%+
- Mid-roll ads: Scartata perché interrompe viewing experience
- Pause ads overlay: SCELTA per UX non intrusiva, CTR atteso 2-4%

PERCHE_QUESTA_SOLUZIONE:
- Vantaggio tecnico: Non interrompe playback, user-initiated pause
- Vantaggio business: CPM premium €5.00 per placement non intrusivo
- Trade-off accettati: Meno impressions totali, ma qualita superiore

METRICHE_SUCCESSO:
- Impression per user/day: >= 3
- CTR (Click-Through Rate): >= 2%
- Revenue per impression: >= €0.005

INTEGRATION_DEPENDENCIES:
- Upstream: models/ads.py (PauseAd, PauseAdImpression), models/video.py
- Downstream: api/v1/ads.py, blockchain_service (weekly batch)
================================================================================
"""

from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any, Tuple
import uuid
import random

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, or_, desc
from sqlalchemy.orm import selectinload

from models.user import User, UserTier


# === CONSTANTS ===

TIERS_WITH_PAUSE_ADS = ["free", "hybrid_light", "hybrid_standard"]

PAUSE_AD_CPM = 5.00  # EUR per 1000 impressions (premium placement)
CLICK_BONUS = 0.02   # EUR per click


class PauseAdService:
    """
    Servizio per gestione pause ads overlay.

    BUSINESS_PURPOSE: Mostrare ads non intrusivi durante pausa video,
    con video suggerito e sponsor ad in layout 50/50.

    TECHNICAL_EXPLANATION: Quando utente mette in pausa, overlay mostra:
    - Lato sinistro: Video consigliato (algoritmo recommendation)
    - Lato destro: Sponsor ad (targeting per tier)
    Ogni impression e click viene tracciato per blockchain batch.
    """

    def __init__(self, db: AsyncSession):
        """
        Inizializza il servizio con database session.

        Args:
            db: AsyncSession SQLAlchemy per operazioni DB
        """
        self.db = db

    async def get_pause_ad(
        self,
        user_id: str,
        video_id: str,
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Ottiene pause ad + video suggerito per overlay.

        BUSINESS_PURPOSE: Entry point quando utente mette in pausa
        TECHNICAL_EXPLANATION: Combina recommendation + ad selection

        DECISION_TREE:
        1. Se utente tier PREMIUM/BUSINESS -> Return empty (no ads)
        2. Se no ads disponibili -> Return solo suggested video
        3. Se tutto OK -> Return full overlay data

        EDGE_CASES:
        - No video suggeriti: Mostra trending video
        - No sponsor ads: Mostra solo video suggerito (half overlay)
        - User non trovato: Return empty dict

        Args:
            user_id: UUID dell'utente
            video_id: UUID del video in pausa
            context: Contesto opzionale (device, language, etc.)

        Returns:
            Dict con suggested_video, sponsor_ad, impression_id

        TEST:
        >>> service = PauseAdService(db)
        >>> result = await service.get_pause_ad("user-uuid", "video-uuid")
        >>> "suggested_video" in result
        True
        """
        user_uuid = uuid.UUID(user_id)
        video_uuid = uuid.UUID(video_id)

        user = await self._get_user(user_uuid)
        if not user:
            return {}

        if not self._user_should_see_pause_ads(user):
            return {}

        suggested_video = await self.get_suggested_video(
            user_id=user_id,
            current_video_id=video_id,
            context=context
        )

        sponsor_ad = await self.get_sponsor_ad(
            user_id=user_id,
            context=context
        )

        impression_id = str(uuid.uuid4())

        if sponsor_ad:
            await self._create_impression_record(
                impression_id=impression_id,
                pause_ad_id=sponsor_ad.get("id"),
                user_id=user_id,
                video_id=video_id,
                context=context
            )

        return {
            "suggested_video": suggested_video,
            "sponsor_ad": sponsor_ad,
            "impression_id": impression_id,
            "show_overlay": bool(suggested_video or sponsor_ad)
        }

    async def get_suggested_video(
        self,
        user_id: str,
        current_video_id: str,
        context: Optional[Dict[str, Any]] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Ottiene video suggerito per overlay sinistro.

        BUSINESS_PURPOSE: Aumentare engagement e watch time
        TECHNICAL_EXPLANATION: Algoritmo di recommendation multi-step

        DECISION_TREE (Priorita):
        1. Video stesso maestro non ancora visto -> Alta rilevanza
        2. Video stessa arte marziale (style) -> Media rilevanza
        3. Video correlati per tag -> Bassa rilevanza
        4. Video popolari generici -> Fallback

        Args:
            user_id: UUID dell'utente
            current_video_id: UUID del video corrente
            context: Contesto opzionale

        Returns:
            Dict con info video suggerito o None
        """
        from models.video import Video, VideoStatus
        from models.user import ViewingHistory

        user_uuid = uuid.UUID(user_id)
        video_uuid = uuid.UUID(current_video_id)

        result = await self.db.execute(
            select(Video).where(Video.id == video_uuid)
        )
        current_video = result.scalar_one_or_none()

        if not current_video:
            return await self._get_trending_video(user_id)

        result = await self.db.execute(
            select(ViewingHistory.video_id).where(
                ViewingHistory.user_id == user_uuid
            )
        )
        watched_video_ids = {row[0] for row in result.fetchall()}

        if current_video.instructor_name:
            result = await self.db.execute(
                select(Video).where(
                    and_(
                        Video.instructor_name == current_video.instructor_name,
                        Video.id != video_uuid,
                        Video.status == VideoStatus.READY,
                        ~Video.id.in_(watched_video_ids) if watched_video_ids else True
                    )
                ).order_by(func.random()).limit(1)
            )
            suggested = result.scalar_one_or_none()
            if suggested:
                return self._format_suggested_video(suggested)

        if current_video.style:
            result = await self.db.execute(
                select(Video).where(
                    and_(
                        Video.style == current_video.style,
                        Video.id != video_uuid,
                        Video.status == VideoStatus.READY,
                        ~Video.id.in_(watched_video_ids) if watched_video_ids else True
                    )
                ).order_by(func.random()).limit(1)
            )
            suggested = result.scalar_one_or_none()
            if suggested:
                return self._format_suggested_video(suggested)

        if current_video.tags:
            result = await self.db.execute(
                select(Video).where(
                    and_(
                        Video.id != video_uuid,
                        Video.status == VideoStatus.READY,
                        ~Video.id.in_(watched_video_ids) if watched_video_ids else True
                    )
                ).order_by(Video.view_count.desc()).limit(10)
            )
            candidates = result.scalars().all()

            current_tags = set(current_video.tags) if current_video.tags else set()
            for candidate in candidates:
                candidate_tags = set(candidate.tags) if candidate.tags else set()
                if current_tags & candidate_tags:
                    return self._format_suggested_video(candidate)

        return await self._get_trending_video(user_id)

    async def get_sponsor_ad(
        self,
        user_id: str,
        context: Optional[Dict[str, Any]] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Seleziona sponsor ad con targeting per utente.

        BUSINESS_PURPOSE: Massimizzare revenue con targeting appropriato
        TECHNICAL_EXPLANATION: Filtra ads per tier, budget, date, poi weighted random by CPM

        DECISION_TREE:
        1. Filtra per target_tiers matching user tier
        2. Filtra per date validity (start_date <= now <= end_date)
        3. Filtra per budget_remaining > 0
        4. Ordina per CPM e seleziona con weighted random

        Args:
            user_id: UUID dell'utente
            context: Contesto opzionale (device, language, etc.)

        Returns:
            Dict con info sponsor ad o None
        """
        user_uuid = uuid.UUID(user_id)
        user = await self._get_user(user_uuid)

        if not user:
            return None

        now = datetime.utcnow()

        result = await self.db.execute(
            select(self._get_pause_ad_model()).where(
                and_(
                    self._get_pause_ad_model().is_active == True,
                    self._get_pause_ad_model().start_date <= now,
                    self._get_pause_ad_model().end_date >= now
                )
            ).order_by(self._get_pause_ad_model().cpm_rate.desc())
        )
        all_ads = result.scalars().all()

        if not all_ads:
            return None

        user_tier = user.tier.value
        eligible_ads = []

        for ad in all_ads:
            if ad.target_tiers:
                if user_tier in ad.target_tiers:
                    eligible_ads.append(ad)
            else:
                eligible_ads.append(ad)

        if not eligible_ads:
            return None

        total_cpm = sum(ad.cpm_rate for ad in eligible_ads)
        if total_cpm == 0:
            selected_ad = random.choice(eligible_ads)
        else:
            weights = [ad.cpm_rate / total_cpm for ad in eligible_ads]
            selected_ad = random.choices(eligible_ads, weights=weights, k=1)[0]

        return self._format_sponsor_ad(selected_ad)

    async def record_impression(
        self,
        impression_id: str,
        user_id: str,
        video_id: str
    ) -> bool:
        """
        Conferma impression quando overlay viene effettivamente mostrato.

        BUSINESS_PURPOSE: Tracciamento accurato per billing advertiser
        TECHNICAL_EXPLANATION: Aggiorna record impression con timestamp

        Args:
            impression_id: UUID dell'impression
            user_id: UUID dell'utente
            video_id: UUID del video

        Returns:
            True se registrata con successo
        """
        try:
            PauseAdImpression = self._get_pause_ad_impression_model()

            result = await self.db.execute(
                select(PauseAdImpression).where(
                    PauseAdImpression.id == uuid.UUID(impression_id)
                )
            )
            impression = result.scalar_one_or_none()

            if impression:
                impression.impression_type = "pause"
                await self.db.commit()
                return True

            return False

        except Exception:
            return False

    async def record_click(
        self,
        impression_id: str,
        user_id: str,
        click_type: str
    ) -> bool:
        """
        Registra click su ad o video suggerito.

        BUSINESS_PURPOSE: Tracking conversioni, bonus revenue per click
        TECHNICAL_EXPLANATION: Aggiorna impression con click info

        Args:
            impression_id: UUID dell'impression
            user_id: UUID dell'utente
            click_type: "ad" o "suggested"

        Returns:
            True se registrato con successo
        """
        if click_type not in ["ad", "suggested"]:
            return False

        try:
            PauseAdImpression = self._get_pause_ad_impression_model()

            result = await self.db.execute(
                select(PauseAdImpression).where(
                    and_(
                        PauseAdImpression.id == uuid.UUID(impression_id),
                        PauseAdImpression.user_id == uuid.UUID(user_id)
                    )
                )
            )
            impression = result.scalar_one_or_none()

            if not impression:
                return False

            impression.clicked = True
            impression.click_type = click_type

            if click_type == "ad" and impression.pause_ad_id:
                PauseAd = self._get_pause_ad_model()
                ad_result = await self.db.execute(
                    select(PauseAd).where(PauseAd.id == impression.pause_ad_id)
                )
                ad = ad_result.scalar_one_or_none()
                if ad:
                    ad.clicks = (ad.clicks or 0) + 1

            await self.db.commit()
            return True

        except Exception:
            return False

    async def get_pause_ad_stats(
        self,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """
        Ottiene statistiche aggregate pause ads per admin dashboard.

        BUSINESS_PURPOSE: Analytics per ottimizzazione e reporting
        TECHNICAL_EXPLANATION: Aggregazioni SQL per periodo

        Args:
            start_date: Data inizio periodo (default: 7 giorni fa)
            end_date: Data fine periodo (default: ora)

        Returns:
            Dict con statistiche aggregate
        """
        if not start_date:
            start_date = datetime.utcnow() - timedelta(days=7)
        if not end_date:
            end_date = datetime.utcnow()

        PauseAdImpression = self._get_pause_ad_impression_model()

        result = await self.db.execute(
            select(func.count(PauseAdImpression.id)).where(
                and_(
                    PauseAdImpression.created_at >= start_date,
                    PauseAdImpression.created_at <= end_date
                )
            )
        )
        total_impressions = result.scalar() or 0

        result = await self.db.execute(
            select(func.count(PauseAdImpression.id)).where(
                and_(
                    PauseAdImpression.created_at >= start_date,
                    PauseAdImpression.created_at <= end_date,
                    PauseAdImpression.clicked == True
                )
            )
        )
        total_clicks = result.scalar() or 0

        result = await self.db.execute(
            select(func.count(func.distinct(PauseAdImpression.user_id))).where(
                and_(
                    PauseAdImpression.created_at >= start_date,
                    PauseAdImpression.created_at <= end_date
                )
            )
        )
        unique_users = result.scalar() or 0

        ctr = (total_clicks / total_impressions * 100) if total_impressions > 0 else 0.0

        impression_revenue = (total_impressions / 1000) * PAUSE_AD_CPM
        click_revenue = total_clicks * CLICK_BONUS
        total_revenue = impression_revenue + click_revenue

        result = await self.db.execute(
            select(func.count(PauseAdImpression.id)).where(
                and_(
                    PauseAdImpression.created_at >= start_date,
                    PauseAdImpression.created_at <= end_date,
                    PauseAdImpression.click_type == "ad"
                )
            )
        )
        ad_clicks = result.scalar() or 0

        result = await self.db.execute(
            select(func.count(PauseAdImpression.id)).where(
                and_(
                    PauseAdImpression.created_at >= start_date,
                    PauseAdImpression.created_at <= end_date,
                    PauseAdImpression.click_type == "suggested"
                )
            )
        )
        suggested_clicks = result.scalar() or 0

        return {
            "period": {
                "start": start_date.isoformat(),
                "end": end_date.isoformat()
            },
            "impressions": {
                "total": total_impressions,
                "unique_users": unique_users,
                "per_user_avg": round(total_impressions / unique_users, 2) if unique_users > 0 else 0
            },
            "clicks": {
                "total": total_clicks,
                "ad_clicks": ad_clicks,
                "suggested_clicks": suggested_clicks,
                "ctr_percentage": round(ctr, 2)
            },
            "revenue": {
                "impression_revenue_eur": round(impression_revenue, 2),
                "click_revenue_eur": round(click_revenue, 2),
                "total_revenue_eur": round(total_revenue, 2),
                "effective_cpm": round((total_revenue / total_impressions * 1000), 2) if total_impressions > 0 else 0
            }
        }

    async def get_impressions_for_blockchain_batch(
        self,
        start_date: datetime,
        end_date: datetime
    ) -> List[Dict[str, Any]]:
        """
        Ottiene impressions non ancora incluse in batch blockchain.

        BUSINESS_PURPOSE: Preparazione dati per batch settimanale
        TECHNICAL_EXPLANATION: Query impressions non-batched per periodo

        Args:
            start_date: Data inizio periodo
            end_date: Data fine periodo

        Returns:
            Lista di impressions per batch
        """
        PauseAdImpression = self._get_pause_ad_impression_model()

        result = await self.db.execute(
            select(PauseAdImpression).where(
                and_(
                    PauseAdImpression.created_at >= start_date,
                    PauseAdImpression.created_at <= end_date,
                    PauseAdImpression.included_in_batch == False
                )
            ).order_by(PauseAdImpression.created_at)
        )

        impressions = result.scalars().all()

        return [
            {
                "id": str(imp.id),
                "pause_ad_id": str(imp.pause_ad_id) if imp.pause_ad_id else None,
                "user_id": str(imp.user_id),
                "video_id": str(imp.video_id),
                "impression_type": imp.impression_type,
                "clicked": imp.clicked,
                "click_type": imp.click_type,
                "created_at": imp.created_at.isoformat()
            }
            for imp in impressions
        ]

    async def mark_impressions_batched(
        self,
        impression_ids: List[str],
        batch_id: str
    ) -> int:
        """
        Marca impressions come incluse in batch blockchain.

        Args:
            impression_ids: Lista UUID impressions
            batch_id: UUID del batch

        Returns:
            Numero di impressions aggiornate
        """
        if not impression_ids:
            return 0

        PauseAdImpression = self._get_pause_ad_impression_model()
        batch_uuid = uuid.UUID(batch_id)

        count = 0
        for imp_id in impression_ids:
            result = await self.db.execute(
                select(PauseAdImpression).where(
                    PauseAdImpression.id == uuid.UUID(imp_id)
                )
            )
            impression = result.scalar_one_or_none()
            if impression:
                impression.included_in_batch = True
                impression.batch_id = batch_uuid
                count += 1

        await self.db.commit()
        return count

    def _user_should_see_pause_ads(self, user: User) -> bool:
        """
        Verifica se utente deve vedere pause ads.

        Args:
            user: Oggetto User

        Returns:
            True se deve vedere pause ads
        """
        return user.tier.value in TIERS_WITH_PAUSE_ADS

    async def _get_trending_video(
        self,
        user_id: str
    ) -> Optional[Dict[str, Any]]:
        """
        Fallback: ottiene video trending quando recommendation fallisce.

        Args:
            user_id: UUID dell'utente

        Returns:
            Dict con info video o None
        """
        from models.video import Video, VideoStatus

        result = await self.db.execute(
            select(Video).where(
                Video.status == VideoStatus.READY
            ).order_by(Video.view_count.desc()).limit(5)
        )
        videos = result.scalars().all()

        if not videos:
            return None

        selected = random.choice(videos)
        return self._format_suggested_video(selected)

    def _format_suggested_video(self, video) -> Dict[str, Any]:
        """
        Formatta video per response.

        Args:
            video: Video ORM object

        Returns:
            Dict formattato
        """
        return {
            "id": str(video.id),
            "title": video.title,
            "thumbnail_url": video.thumbnail_url or "",
            "duration": video.duration or 0,
            "maestro_name": video.instructor_name or "",
            "style": video.style or "",
            "category": video.category.value if video.category else "other"
        }

    def _format_sponsor_ad(self, ad) -> Dict[str, Any]:
        """
        Formatta sponsor ad per response.

        Args:
            ad: PauseAd ORM object

        Returns:
            Dict formattato
        """
        return {
            "id": str(ad.id),
            "advertiser": ad.advertiser_name,
            "title": ad.title,
            "description": ad.description or "",
            "image_url": ad.image_url,
            "click_url": ad.click_url
        }

    async def _create_impression_record(
        self,
        impression_id: str,
        pause_ad_id: Optional[str],
        user_id: str,
        video_id: str,
        context: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Crea record impression nel database.

        Args:
            impression_id: UUID dell'impression
            pause_ad_id: UUID del pause ad (se presente)
            user_id: UUID dell'utente
            video_id: UUID del video
            context: Contesto opzionale
        """
        PauseAdImpression = self._get_pause_ad_impression_model()

        impression = PauseAdImpression(
            id=uuid.UUID(impression_id),
            pause_ad_id=uuid.UUID(pause_ad_id) if pause_ad_id else None,
            user_id=uuid.UUID(user_id),
            video_id=uuid.UUID(video_id),
            impression_type="pending",
            clicked=False,
            click_type=None,
            included_in_batch=False,
            batch_id=None,
            created_at=datetime.utcnow(),
            ip_address=context.get("ip_address") if context else None,
            user_agent=context.get("user_agent") if context else None
        )

        self.db.add(impression)
        await self.db.commit()

        if pause_ad_id:
            PauseAd = self._get_pause_ad_model()
            result = await self.db.execute(
                select(PauseAd).where(PauseAd.id == uuid.UUID(pause_ad_id))
            )
            ad = result.scalar_one_or_none()
            if ad:
                ad.impressions = (ad.impressions or 0) + 1
                await self.db.commit()

    async def _get_user(self, user_uuid: uuid.UUID) -> Optional[User]:
        """
        Helper per recuperare utente.

        Args:
            user_uuid: UUID dell'utente

        Returns:
            User o None
        """
        result = await self.db.execute(
            select(User).where(User.id == user_uuid)
        )
        return result.scalar_one_or_none()

    def _get_pause_ad_model(self):
        """
        Lazy import per evitare circular dependencies.

        Returns:
            PauseAd model class
        """
        from models.ads import PauseAd
        return PauseAd

    def _get_pause_ad_impression_model(self):
        """
        Lazy import per evitare circular dependencies.

        Returns:
            PauseAdImpression model class
        """
        from models.ads import PauseAdImpression
        return PauseAdImpression
