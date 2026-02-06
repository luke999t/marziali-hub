"""
AI_MODULE: Special Projects Service Layer
AI_DESCRIPTION: Business logic per gestione progetti e votazioni
AI_BUSINESS: Orchestrazione completa flusso votazione, audit completo
AI_TEACHING: Service pattern, transaction management, event-driven updates

ALTERNATIVE_VALUTATE:
- Fat controllers: Scartato, logic dispersa
- Event sourcing: Scartato, overkill per MVP
- Direct DB access: Scartato, no business validation

PERCHE_QUESTA_SOLUZIONE:
- Service layer: Centralizza logica, testabile
- Transaction boundaries: ACID per voti
- Denormalized stats: Performance read, update on write

METRICHE_SUCCESSO:
- Vote transaction: <50ms
- Project list: <30ms
- Vote integrity: 100%
"""

import logging
import re
from datetime import datetime, timedelta
from typing import Optional, List, Tuple, Dict, Any
from uuid import UUID

from sqlalchemy import select, func, update, and_, or_
from sqlalchemy.ext.asyncio import AsyncSession

from .config import SpecialProjectsConfig, get_special_projects_config
from .models import (
    SpecialProject,
    ProjectVote,
    VotingEligibility,
    VoteHistory,
    ProjectStatus,
    EligibilityStatus
)
from .schemas import (
    SpecialProjectCreate,
    SpecialProjectUpdate,
    ProjectVoteCreate
)
from .eligibility import EligibilityCalculator

logger = logging.getLogger(__name__)


class SpecialProjectsService:
    """
    Service per gestione progetti speciali e votazioni.

    Responsabilita:
    - CRUD progetti
    - Gestione voti
    - Validazione business rules
    - Aggiornamento stats
    """

    def __init__(
        self,
        db: AsyncSession,
        config: Optional[SpecialProjectsConfig] = None
    ):
        self.db = db
        self.config = config or get_special_projects_config()
        self.eligibility_calculator = EligibilityCalculator(db, self.config)

    # ======================== PROJECTS ========================

    async def create_project(
        self,
        data: SpecialProjectCreate,
        created_by: UUID
    ) -> SpecialProject:
        """
        Crea nuovo progetto speciale.

        Args:
            data: Dati progetto
            created_by: ID admin creatore

        Returns:
            SpecialProject creato
        """
        # Generate slug
        slug = self._generate_slug(data.title)

        # Check slug uniqueness
        existing = await self.db.execute(
            select(SpecialProject).where(SpecialProject.slug == slug)
        )
        if existing.scalar_one_or_none():
            slug = f"{slug}-{datetime.utcnow().strftime('%Y%m%d%H%M')}"

        project = SpecialProject(
            title=data.title,
            slug=slug,
            description=data.description,
            short_description=data.short_description,
            image_url=data.image_url,
            video_url=data.video_url,
            estimated_budget_cents=data.estimated_budget_cents,
            estimated_days=data.estimated_days,
            funding_goal_cents=data.funding_goal_cents,
            tags=data.tags,
            voting_start_date=data.voting_start_date,
            voting_end_date=data.voting_end_date,
            status=ProjectStatus.DRAFT,
            created_by=created_by
        )

        self.db.add(project)
        await self.db.flush()

        logger.info(f"Created project {project.id}: {project.title}")
        return project

    def _generate_slug(self, title: str) -> str:
        """Genera slug URL-friendly da titolo."""
        slug = title.lower()
        slug = re.sub(r'[^a-z0-9\s-]', '', slug)
        slug = re.sub(r'[\s_]+', '-', slug)
        slug = re.sub(r'-+', '-', slug)
        return slug.strip('-')[:100]

    async def update_project(
        self,
        project_id: UUID,
        data: SpecialProjectUpdate
    ) -> Optional[SpecialProject]:
        """Aggiorna progetto esistente."""
        project = await self.get_project(project_id)
        if not project:
            return None

        update_data = data.model_dump(exclude_unset=True)

        for field, value in update_data.items():
            if value is not None:
                if field == 'status':
                    value = ProjectStatus(value)
                setattr(project, field, value)

        project.updated_at = datetime.utcnow()

        # If publishing, set published_at
        if data.status == ProjectStatus.ACTIVE and not project.published_at:
            project.published_at = datetime.utcnow()

        await self.db.flush()
        return project

    async def get_project(self, project_id: UUID) -> Optional[SpecialProject]:
        """Ottiene progetto per ID."""
        result = await self.db.execute(
            select(SpecialProject).where(
                SpecialProject.id == project_id,
                SpecialProject.is_deleted == False
            )
        )
        return result.scalar_one_or_none()

    async def get_project_by_slug(self, slug: str) -> Optional[SpecialProject]:
        """Ottiene progetto per slug."""
        result = await self.db.execute(
            select(SpecialProject).where(
                SpecialProject.slug == slug,
                SpecialProject.is_deleted == False
            )
        )
        return result.scalar_one_or_none()

    async def list_projects(
        self,
        status: Optional[ProjectStatus] = None,
        include_drafts: bool = False,
        page: int = 1,
        page_size: int = 20
    ) -> Tuple[List[SpecialProject], int]:
        """
        Lista progetti con filtri e paginazione.

        Args:
            status: Filtra per status
            include_drafts: Include progetti draft
            page: Pagina (1-indexed)
            page_size: Elementi per pagina

        Returns:
            Tuple (projects, total_count)
        """
        query = select(SpecialProject).where(SpecialProject.is_deleted == False)

        if status:
            query = query.where(SpecialProject.status == status)
        elif not include_drafts:
            query = query.where(SpecialProject.status != ProjectStatus.DRAFT)

        # Count total
        count_query = select(func.count()).select_from(query.subquery())
        total_result = await self.db.execute(count_query)
        total = total_result.scalar() or 0

        # Apply pagination and ordering
        query = query.order_by(
            SpecialProject.total_weighted_votes.desc(),
            SpecialProject.created_at.desc()
        ).offset((page - 1) * page_size).limit(page_size)

        result = await self.db.execute(query)
        projects = list(result.scalars().all())

        return projects, total

    async def list_active_for_voting(self) -> List[SpecialProject]:
        """Lista progetti attivi aperti al voto."""
        now = datetime.utcnow()

        result = await self.db.execute(
            select(SpecialProject).where(
                SpecialProject.status == ProjectStatus.ACTIVE,
                SpecialProject.is_deleted == False,
                or_(
                    SpecialProject.voting_start_date.is_(None),
                    SpecialProject.voting_start_date <= now
                ),
                or_(
                    SpecialProject.voting_end_date.is_(None),
                    SpecialProject.voting_end_date >= now
                )
            ).order_by(SpecialProject.total_weighted_votes.desc())
        )
        return list(result.scalars().all())

    # ======================== VOTING ========================

    async def vote(
        self,
        user_id: UUID,
        data: ProjectVoteCreate
    ) -> Tuple[Optional[ProjectVote], str]:
        """
        Registra voto utente su progetto.

        Args:
            user_id: ID utente votante
            data: Dati voto (project_id, confirm_change)

        Returns:
            Tuple (ProjectVote, message)
        """
        cycle = self.eligibility_calculator.get_current_vote_cycle()

        # 1. Check eligibility
        eligibility = await self.eligibility_calculator.check_eligibility(user_id)
        if not eligibility.is_eligible():
            return None, f"Not eligible to vote: {eligibility.ineligibility_reason}"

        # 2. Check project exists and is votable
        project = await self.get_project(data.project_id)
        if not project:
            return None, "Project not found"

        if not project.is_voting_open():
            return None, "Voting is not open for this project"

        # 3. Check existing vote
        existing_vote = await self._get_user_active_vote(user_id, cycle)

        if existing_vote:
            # Already voted
            if existing_vote.project_id == data.project_id:
                return None, "You have already voted for this project"

            # Changing vote
            if not self.config.voting_rules.can_change_vote_same_cycle:
                if not data.confirm_change:
                    return None, "You have already voted this cycle. Set confirm_change=true to change your vote."

            # Process vote change
            return await self._change_vote(existing_vote, project, eligibility)

        # 4. Create new vote
        return await self._create_vote(user_id, project, eligibility, cycle)

    async def _get_user_active_vote(
        self,
        user_id: UUID,
        cycle: str
    ) -> Optional[ProjectVote]:
        """Ottiene voto attivo utente per ciclo."""
        result = await self.db.execute(
            select(ProjectVote).where(
                ProjectVote.user_id == user_id,
                ProjectVote.vote_cycle == cycle,
                ProjectVote.is_active == True
            )
        )
        return result.scalar_one_or_none()

    async def _create_vote(
        self,
        user_id: UUID,
        project: SpecialProject,
        eligibility: VotingEligibility,
        cycle: str
    ) -> Tuple[ProjectVote, str]:
        """Crea nuovo voto."""
        vote = ProjectVote(
            user_id=user_id,
            project_id=project.id,
            vote_weight=eligibility.vote_weight,
            subscription_tier_at_vote=eligibility.subscription_tier,
            vote_cycle=cycle,
            is_active=True
        )

        self.db.add(vote)

        # Update project stats
        project.total_votes += 1
        project.total_weighted_votes += eligibility.vote_weight
        project.unique_voters += 1

        await self.db.flush()

        logger.info(f"User {user_id} voted for project {project.id} with weight {eligibility.vote_weight}")

        return vote, "Vote recorded successfully"

    async def _change_vote(
        self,
        existing_vote: ProjectVote,
        new_project: SpecialProject,
        eligibility: VotingEligibility
    ) -> Tuple[ProjectVote, str]:
        """Cambia voto esistente."""
        old_project_id = existing_vote.project_id
        old_weight = existing_vote.vote_weight

        # Record history
        if self.config.voting_rules.track_vote_changes:
            history = VoteHistory(
                user_id=existing_vote.user_id,
                from_project_id=old_project_id,
                to_project_id=new_project.id,
                vote_cycle=existing_vote.vote_cycle,
                vote_weight=eligibility.vote_weight,
                subscription_tier=eligibility.subscription_tier
            )
            self.db.add(history)

        # Update old project stats
        old_project = await self.get_project(old_project_id)
        if old_project:
            old_project.total_votes -= 1
            old_project.total_weighted_votes -= old_weight
            old_project.unique_voters -= 1

        # Update vote
        existing_vote.project_id = new_project.id
        existing_vote.vote_weight = eligibility.vote_weight
        existing_vote.subscription_tier_at_vote = eligibility.subscription_tier
        existing_vote.previous_project_id = old_project_id
        existing_vote.changed_from_previous = True
        existing_vote.updated_at = datetime.utcnow()

        # Update new project stats
        new_project.total_votes += 1
        new_project.total_weighted_votes += eligibility.vote_weight
        new_project.unique_voters += 1

        await self.db.flush()

        logger.info(f"User {existing_vote.user_id} changed vote from {old_project_id} to {new_project.id}")

        return existing_vote, "Vote changed successfully"

    async def get_user_current_vote(self, user_id: UUID) -> Optional[ProjectVote]:
        """Ottiene voto corrente utente."""
        cycle = self.eligibility_calculator.get_current_vote_cycle()
        return await self._get_user_active_vote(user_id, cycle)

    async def get_user_vote_history(
        self,
        user_id: UUID,
        limit: int = 12
    ) -> List[ProjectVote]:
        """Ottiene storico voti utente (ultimi N cicli)."""
        result = await self.db.execute(
            select(ProjectVote).where(
                ProjectVote.user_id == user_id
            ).order_by(
                ProjectVote.vote_cycle.desc(),
                ProjectVote.voted_at.desc()
            ).limit(limit)
        )
        return list(result.scalars().all())

    # ======================== ELIGIBILITY ========================

    async def check_user_eligibility(
        self,
        user_id: UUID,
        force_recalculate: bool = False
    ) -> VotingEligibility:
        """Proxy per eligibility calculator."""
        return await self.eligibility_calculator.check_eligibility(
            user_id, force_recalculate
        )

    # ======================== STATS ========================

    async def get_voting_stats(self, cycle: Optional[str] = None) -> Dict[str, Any]:
        """
        Ottiene statistiche votazione per ciclo.

        Args:
            cycle: Ciclo voto (default: corrente)

        Returns:
            Dict con statistiche aggregate
        """
        cycle = cycle or self.eligibility_calculator.get_current_vote_cycle()

        # Total votes
        votes_result = await self.db.execute(
            select(
                func.count(ProjectVote.id).label("total"),
                func.sum(ProjectVote.vote_weight).label("weighted")
            ).where(
                ProjectVote.vote_cycle == cycle,
                ProjectVote.is_active == True
            )
        )
        votes_data = votes_result.one()

        # Votes by tier
        tier_result = await self.db.execute(
            select(
                ProjectVote.subscription_tier_at_vote,
                func.count(ProjectVote.id),
                func.sum(ProjectVote.vote_weight)
            ).where(
                ProjectVote.vote_cycle == cycle,
                ProjectVote.is_active == True
            ).group_by(ProjectVote.subscription_tier_at_vote)
        )

        votes_by_tier = {}
        weighted_by_tier = {}
        for row in tier_result.all():
            votes_by_tier[row[0]] = row[1]
            weighted_by_tier[row[0]] = row[2]

        # Eligible users
        eligible_count = await self.eligibility_calculator.get_eligible_users_count(cycle)

        # Top projects
        projects, _ = await self.list_projects(status=ProjectStatus.ACTIVE)
        top_projects = [
            {
                "id": str(p.id),
                "title": p.title,
                "votes": p.total_votes,
                "weighted_votes": p.total_weighted_votes
            }
            for p in projects[:5]
        ]

        participation_rate = (votes_data.total / eligible_count * 100) if eligible_count > 0 else 0

        return {
            "vote_cycle": cycle,
            "total_eligible_voters": eligible_count,
            "total_votes_cast": votes_data.total or 0,
            "total_weighted_votes": votes_data.weighted or 0,
            "participation_rate": round(participation_rate, 2),
            "votes_by_tier": votes_by_tier,
            "weighted_votes_by_tier": weighted_by_tier,
            "top_projects": top_projects
        }

    async def close_voting_cycle(self, cycle: Optional[str] = None) -> Dict[str, Any]:
        """
        Chiude ciclo votazione e determina vincitore.

        Args:
            cycle: Ciclo da chiudere

        Returns:
            Risultati votazione
        """
        cycle = cycle or self.eligibility_calculator.get_current_vote_cycle()

        # Get winner
        result = await self.db.execute(
            select(SpecialProject).where(
                SpecialProject.status == ProjectStatus.ACTIVE,
                SpecialProject.is_deleted == False
            ).order_by(SpecialProject.total_weighted_votes.desc()).limit(1)
        )
        winner = result.scalar_one_or_none()

        if winner:
            # Update winner status
            winner.status = ProjectStatus.APPROVED

            # Close other active projects
            await self.db.execute(
                update(SpecialProject).where(
                    SpecialProject.status == ProjectStatus.ACTIVE,
                    SpecialProject.id != winner.id
                ).values(status=ProjectStatus.VOTING_CLOSED)
            )

        await self.db.flush()

        stats = await self.get_voting_stats(cycle)
        stats["winner_project_id"] = str(winner.id) if winner else None
        stats["winner_title"] = winner.title if winner else None

        logger.info(f"Closed voting cycle {cycle}. Winner: {winner.title if winner else 'None'}")

        return stats
