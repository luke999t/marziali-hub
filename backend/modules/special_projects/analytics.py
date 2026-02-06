"""
AI_MODULE: Special Projects Analytics
AI_DESCRIPTION: Analytics avanzate per sistema votazione progetti
AI_BUSINESS: Insights partecipazione, conversioni, trend analysis
AI_TEACHING: SQL aggregations, time series, cohort analysis

ALTERNATIVE_VALUTATE:
- External BI tool: Scartato, latenza alta
- Real-time streaming: Scartato, overkill per volume
- Pre-computed only: Scartato, miss fresh data

PERCHE_QUESTA_SOLUZIONE:
- Hybrid approach: Pre-computed + on-demand
- SQL native: Leverage PostgreSQL analytics
- Cacheable: Results cacheable at API level

METRICHE_SUCCESSO:
- Dashboard load: <500ms
- Report generation: <2s
- Data freshness: <1 hour
"""

import logging
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from uuid import UUID

from sqlalchemy import select, func, and_, case, text
from sqlalchemy.ext.asyncio import AsyncSession

from .models import (
    SpecialProject,
    ProjectVote,
    VotingEligibility,
    VoteHistory,
    ProjectStatus,
    EligibilityStatus
)
from .config import get_special_projects_config

logger = logging.getLogger(__name__)


class SpecialProjectsAnalytics:
    """
    Analytics per sistema progetti speciali.

    Fornisce:
    - Metriche partecipazione
    - Trend temporali
    - Cohort analysis
    - Conversion funnel
    """

    def __init__(self, db: AsyncSession):
        self.db = db
        self.config = get_special_projects_config()

    # ======================== PARTICIPATION METRICS ========================

    async def get_participation_summary(
        self,
        cycle: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Summary partecipazione votazione.

        Args:
            cycle: Ciclo specifico (default: corrente)

        Returns:
            Dict con metriche partecipazione
        """
        if not cycle:
            now = datetime.utcnow()
            cycle = f"{now.year}-{now.month:02d}"

        # Total eligible
        eligible_result = await self.db.execute(
            select(func.count(VotingEligibility.id)).where(
                VotingEligibility.vote_cycle == cycle,
                VotingEligibility.status == EligibilityStatus.ELIGIBLE
            )
        )
        total_eligible = eligible_result.scalar() or 0

        # Total voted
        voted_result = await self.db.execute(
            select(func.count(func.distinct(ProjectVote.user_id))).where(
                ProjectVote.vote_cycle == cycle,
                ProjectVote.is_active == True
            )
        )
        total_voted = voted_result.scalar() or 0

        # By tier breakdown
        tier_breakdown = await self.db.execute(
            select(
                ProjectVote.subscription_tier_at_vote,
                func.count(ProjectVote.id).label("count"),
                func.sum(ProjectVote.vote_weight).label("weighted")
            ).where(
                ProjectVote.vote_cycle == cycle,
                ProjectVote.is_active == True
            ).group_by(ProjectVote.subscription_tier_at_vote)
        )

        by_tier = {
            row[0]: {"count": row[1], "weighted_votes": row[2]}
            for row in tier_breakdown.all()
        }

        participation_rate = (total_voted / total_eligible * 100) if total_eligible > 0 else 0

        return {
            "cycle": cycle,
            "total_eligible_users": total_eligible,
            "total_voted_users": total_voted,
            "participation_rate": round(participation_rate, 2),
            "breakdown_by_tier": by_tier
        }

    async def get_participation_trend(
        self,
        months: int = 6
    ) -> List[Dict[str, Any]]:
        """
        Trend partecipazione ultimi N mesi.

        Returns:
            Lista con dati per mese
        """
        results = []
        now = datetime.utcnow()

        for i in range(months):
            date = now - timedelta(days=30 * i)
            cycle = f"{date.year}-{date.month:02d}"

            summary = await self.get_participation_summary(cycle)
            results.append({
                "cycle": cycle,
                "eligible": summary["total_eligible_users"],
                "voted": summary["total_voted_users"],
                "rate": summary["participation_rate"]
            })

        return list(reversed(results))

    # ======================== PROJECT METRICS ========================

    async def get_project_ranking(
        self,
        cycle: Optional[str] = None,
        limit: int = 10
    ) -> List[Dict[str, Any]]:
        """
        Ranking progetti per weighted votes.
        """
        result = await self.db.execute(
            select(SpecialProject).where(
                SpecialProject.status.in_([
                    ProjectStatus.ACTIVE,
                    ProjectStatus.VOTING_CLOSED,
                    ProjectStatus.APPROVED
                ]),
                SpecialProject.is_deleted == False
            ).order_by(
                SpecialProject.total_weighted_votes.desc()
            ).limit(limit)
        )

        projects = result.scalars().all()

        ranking = []
        for idx, project in enumerate(projects, 1):
            ranking.append({
                "rank": idx,
                "project_id": str(project.id),
                "title": project.title,
                "slug": project.slug,
                "total_votes": project.total_votes,
                "weighted_votes": project.total_weighted_votes,
                "unique_voters": project.unique_voters,
                "status": project.status.value
            })

        return ranking

    async def get_project_vote_breakdown(
        self,
        project_id: UUID
    ) -> Dict[str, Any]:
        """
        Breakdown voti per singolo progetto.
        """
        # Basic stats
        result = await self.db.execute(
            select(SpecialProject).where(SpecialProject.id == project_id)
        )
        project = result.scalar_one_or_none()

        if not project:
            return {"error": "Project not found"}

        # By tier
        tier_result = await self.db.execute(
            select(
                ProjectVote.subscription_tier_at_vote,
                func.count(ProjectVote.id),
                func.sum(ProjectVote.vote_weight)
            ).where(
                ProjectVote.project_id == project_id,
                ProjectVote.is_active == True
            ).group_by(ProjectVote.subscription_tier_at_vote)
        )

        by_tier = {
            row[0]: {"count": row[1], "weighted": row[2]}
            for row in tier_result.all()
        }

        # Vote timeline (last 30 days)
        thirty_days_ago = datetime.utcnow() - timedelta(days=30)
        timeline_result = await self.db.execute(
            select(
                func.date(ProjectVote.voted_at).label("date"),
                func.count(ProjectVote.id).label("count")
            ).where(
                ProjectVote.project_id == project_id,
                ProjectVote.voted_at >= thirty_days_ago
            ).group_by(func.date(ProjectVote.voted_at)).order_by(text("date"))
        )

        timeline = [
            {"date": str(row[0]), "votes": row[1]}
            for row in timeline_result.all()
        ]

        return {
            "project_id": str(project.id),
            "title": project.title,
            "total_votes": project.total_votes,
            "weighted_votes": project.total_weighted_votes,
            "unique_voters": project.unique_voters,
            "breakdown_by_tier": by_tier,
            "vote_timeline": timeline
        }

    # ======================== CONVERSION METRICS ========================

    async def get_conversion_funnel(
        self,
        cycle: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Funnel conversione: eligible -> voted.
        """
        if not cycle:
            now = datetime.utcnow()
            cycle = f"{now.year}-{now.month:02d}"

        # Stage 1: All users
        from models import User
        total_users_result = await self.db.execute(
            select(func.count(User.id)).where(User.is_active == True)
        )
        total_users = total_users_result.scalar() or 0

        # Stage 2: Eligible to vote
        eligible_result = await self.db.execute(
            select(func.count(VotingEligibility.id)).where(
                VotingEligibility.vote_cycle == cycle,
                VotingEligibility.status == EligibilityStatus.ELIGIBLE
            )
        )
        eligible_users = eligible_result.scalar() or 0

        # Stage 3: Actually voted
        voted_result = await self.db.execute(
            select(func.count(func.distinct(ProjectVote.user_id))).where(
                ProjectVote.vote_cycle == cycle,
                ProjectVote.is_active == True
            )
        )
        voted_users = voted_result.scalar() or 0

        return {
            "cycle": cycle,
            "funnel": [
                {
                    "stage": "total_users",
                    "count": total_users,
                    "rate": 100.0
                },
                {
                    "stage": "eligible_to_vote",
                    "count": eligible_users,
                    "rate": round(eligible_users / total_users * 100, 2) if total_users > 0 else 0
                },
                {
                    "stage": "voted",
                    "count": voted_users,
                    "rate": round(voted_users / eligible_users * 100, 2) if eligible_users > 0 else 0
                }
            ]
        }

    async def get_free_user_conversion(
        self,
        cycle: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Metriche conversione utenti free a eligible.
        """
        if not cycle:
            now = datetime.utcnow()
            cycle = f"{now.year}-{now.month:02d}"

        # Free users total
        free_total = await self.db.execute(
            select(func.count(VotingEligibility.id)).where(
                VotingEligibility.vote_cycle == cycle,
                VotingEligibility.subscription_tier == "free_with_ads"
            )
        )
        total_free = free_total.scalar() or 0

        # Free users eligible (met requirements)
        free_eligible = await self.db.execute(
            select(func.count(VotingEligibility.id)).where(
                VotingEligibility.vote_cycle == cycle,
                VotingEligibility.subscription_tier == "free_with_ads",
                VotingEligibility.status == EligibilityStatus.ELIGIBLE
            )
        )
        total_free_eligible = free_eligible.scalar() or 0

        # Free users pending (close to eligible)
        free_pending = await self.db.execute(
            select(func.count(VotingEligibility.id)).where(
                VotingEligibility.vote_cycle == cycle,
                VotingEligibility.subscription_tier == "free_with_ads",
                VotingEligibility.status == EligibilityStatus.PENDING
            )
        )
        total_free_pending = free_pending.scalar() or 0

        # Average progress for not eligible
        avg_progress = await self.db.execute(
            select(func.avg(VotingEligibility.progress_percent)).where(
                VotingEligibility.vote_cycle == cycle,
                VotingEligibility.subscription_tier == "free_with_ads",
                VotingEligibility.status == EligibilityStatus.NOT_ELIGIBLE
            )
        )
        avg = avg_progress.scalar() or 0

        conversion_rate = (total_free_eligible / total_free * 100) if total_free > 0 else 0

        return {
            "cycle": cycle,
            "total_free_users": total_free,
            "free_users_eligible": total_free_eligible,
            "free_users_pending": total_free_pending,
            "conversion_rate": round(conversion_rate, 2),
            "avg_progress_not_eligible": round(avg, 2)
        }

    # ======================== VOTE CHANGE ANALYSIS ========================

    async def get_vote_change_stats(
        self,
        cycle: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Statistiche cambi voto.
        """
        if not cycle:
            now = datetime.utcnow()
            cycle = f"{now.year}-{now.month:02d}"

        # Total changes
        changes_result = await self.db.execute(
            select(func.count(VoteHistory.id)).where(
                VoteHistory.vote_cycle == cycle
            )
        )
        total_changes = changes_result.scalar() or 0

        # Total votes
        votes_result = await self.db.execute(
            select(func.count(ProjectVote.id)).where(
                ProjectVote.vote_cycle == cycle
            )
        )
        total_votes = votes_result.scalar() or 0

        # Most changed from
        changed_from = await self.db.execute(
            select(
                VoteHistory.from_project_id,
                func.count(VoteHistory.id).label("count")
            ).where(
                VoteHistory.vote_cycle == cycle,
                VoteHistory.from_project_id.isnot(None)
            ).group_by(VoteHistory.from_project_id).order_by(
                text("count DESC")
            ).limit(5)
        )

        lost_votes = []
        for row in changed_from.all():
            project = await self.db.execute(
                select(SpecialProject).where(SpecialProject.id == row[0])
            )
            p = project.scalar_one_or_none()
            if p:
                lost_votes.append({
                    "project_id": str(p.id),
                    "title": p.title,
                    "votes_lost": row[1]
                })

        change_rate = (total_changes / total_votes * 100) if total_votes > 0 else 0

        return {
            "cycle": cycle,
            "total_votes": total_votes,
            "total_changes": total_changes,
            "change_rate": round(change_rate, 2),
            "projects_losing_votes": lost_votes
        }

    # ======================== AGGREGATE DASHBOARD ========================

    async def get_dashboard_data(
        self,
        cycle: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Dati aggregati per dashboard admin.
        """
        participation = await self.get_participation_summary(cycle)
        ranking = await self.get_project_ranking(cycle, limit=5)
        funnel = await self.get_conversion_funnel(cycle)
        free_conversion = await self.get_free_user_conversion(cycle)
        vote_changes = await self.get_vote_change_stats(cycle)
        trend = await self.get_participation_trend(6)

        # Active projects count
        active_result = await self.db.execute(
            select(func.count(SpecialProject.id)).where(
                SpecialProject.status == ProjectStatus.ACTIVE,
                SpecialProject.is_deleted == False
            )
        )
        active_projects = active_result.scalar() or 0

        return {
            "cycle": participation["cycle"],
            "summary": {
                "active_projects": active_projects,
                "total_eligible": participation["total_eligible_users"],
                "total_voted": participation["total_voted_users"],
                "participation_rate": participation["participation_rate"]
            },
            "top_projects": ranking,
            "funnel": funnel["funnel"],
            "free_user_conversion": free_conversion,
            "vote_changes": vote_changes,
            "participation_trend": trend
        }
