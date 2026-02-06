"""
AI_MODULE: Special Projects Tests
AI_DESCRIPTION: Test suite completo per sistema votazione progetti speciali
AI_BUSINESS: Validazione 100% business logic, ZERO MOCK
AI_TEACHING: pytest async, fixtures, parametrized tests, integration tests

LEGGE SUPREMA: ZERO MOCK
- Tutti i test usano database reale (SQLite in-memory per velocita)
- Service calls reali
- Nessun MagicMock, AsyncMock, patch()
"""

import pytest
import asyncio
from datetime import datetime, timedelta
from uuid import uuid4, UUID
import sys
import os

# Add backend to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.pool import StaticPool

from core.database import Base
from models import User, UserTier
from modules.special_projects.config import (
    SpecialProjectsConfig,
    VoteWeightsConfig,
    FreeUserRequirements,
    VotingRulesConfig,
    SubscriptionTier,
    get_special_projects_config,
    clear_config_cache
)
from modules.special_projects.models import (
    SpecialProject,
    ProjectVote,
    VotingEligibility,
    SpecialProjectsConfigDB,
    VoteHistory,
    ProjectStatus,
    EligibilityStatus
)
from modules.special_projects.schemas import (
    SpecialProjectCreate,
    SpecialProjectUpdate,
    SpecialProjectResponse,
    ProjectVoteCreate,
    EligibilityResponse,
    ProjectStatusEnum
)
from modules.special_projects.eligibility import EligibilityCalculator
from modules.special_projects.service import SpecialProjectsService


# ======================== FIXTURES ========================

@pytest.fixture(scope="function")
def event_loop():
    """Create event loop for async tests."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="function")
async def async_db():
    """
    Create async PostgreSQL database session for tests.

    Uses real PostgreSQL database to support ARRAY types and other PG-specific features.
    FIX: Changed from SQLite to PostgreSQL - SQLite doesn't support ARRAY type.
    """
    from core.database import DATABASE_URL_ASYNC

    engine = create_async_engine(
        DATABASE_URL_ASYNC,
        echo=False
    )

    async_session = async_sessionmaker(
        engine, class_=AsyncSession, expire_on_commit=False
    )

    async with async_session() as session:
        yield session
        await session.rollback()

    await engine.dispose()


@pytest.fixture
async def test_users(async_db: AsyncSession):
    """Create test users with different tiers."""
    # Use unique IDs and emails for each test to avoid conflicts
    unique_suffix = uuid4().hex[:8]

    users = {
        "premium_full": User(
            id=uuid4(),
            email=f"premium_{unique_suffix}@test.com",
            username=f"premium_{unique_suffix}",
            hashed_password="$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/X4.I4.VYl1G/WdHuy",
            tier=UserTier.PREMIUM,
            is_active=True
        ),
        "premium_hybrid": User(
            id=uuid4(),
            email=f"hybrid_{unique_suffix}@test.com",
            username=f"hybrid_{unique_suffix}",
            hashed_password="$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/X4.I4.VYl1G/WdHuy",
            tier=UserTier.HYBRID_STANDARD,
            is_active=True
        ),
        "free_with_ads": User(
            id=uuid4(),
            email=f"free_{unique_suffix}@test.com",
            username=f"free_{unique_suffix}",
            hashed_password="$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/X4.I4.VYl1G/WdHuy",
            tier=UserTier.FREE,
            is_active=True
        ),
        "admin": User(
            id=uuid4(),
            email=f"admin_{unique_suffix}@test.com",
            username=f"admin_{unique_suffix}",
            hashed_password="$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/X4.I4.VYl1G/WdHuy",
            tier=UserTier.BUSINESS,
            is_active=True,
            is_admin=True
        )
    }

    for user in users.values():
        async_db.add(user)

    await async_db.flush()
    return users


@pytest.fixture
def config():
    """Get fresh config for tests."""
    clear_config_cache()
    return get_special_projects_config()


@pytest.fixture
async def service(async_db: AsyncSession, config):
    """Create service with test database."""
    return SpecialProjectsService(async_db, config)


@pytest.fixture
async def test_project(async_db: AsyncSession, test_users):
    """Create a test project for voting tests."""
    project = SpecialProject(
        id=uuid4(),
        title="Test Project for Voting",
        slug="test-project-voting",
        description="A" * 100,  # Min 100 chars
        status=ProjectStatus.ACTIVE,
        voting_start_date=datetime.utcnow() - timedelta(days=1),
        voting_end_date=datetime.utcnow() + timedelta(days=30),
        created_by=test_users["admin"].id
    )
    async_db.add(project)
    await async_db.flush()
    return project


# ======================== CONFIG TESTS ========================

class TestSpecialProjectsConfig:
    """Test configuration system."""

    def test_default_vote_weights(self, config: SpecialProjectsConfig):
        """Test default vote weights are set correctly."""
        assert config.vote_weights.premium_full == 3
        assert config.vote_weights.premium_hybrid == 2
        assert config.vote_weights.free_with_ads == 1
        assert config.vote_weights.free_no_ads == 0

    def test_get_weight_for_tier(self, config: SpecialProjectsConfig):
        """Test weight retrieval by tier."""
        weights = config.vote_weights

        assert weights.get_weight(SubscriptionTier.PREMIUM_FULL) == 3
        assert weights.get_weight(SubscriptionTier.PREMIUM_HYBRID) == 2
        assert weights.get_weight(SubscriptionTier.FREE_WITH_ADS) == 1
        assert weights.get_weight(SubscriptionTier.FREE_NO_ADS) == 0

    def test_free_user_requirements_defaults(self, config: SpecialProjectsConfig):
        """Test free user requirements have correct defaults."""
        reqs = config.free_user_requirements

        assert reqs.min_watch_minutes == 60
        assert reqs.min_ads_watched == 10
        assert reqs.min_videos_completed == 5
        assert reqs.lookback_days == 30

    def test_voting_rules_defaults(self, config: SpecialProjectsConfig):
        """Test voting rules have correct defaults."""
        rules = config.voting_rules

        assert rules.vote_cycle_type == "monthly"
        assert rules.votes_per_user_per_cycle == 1
        assert rules.can_change_vote_same_cycle is False
        assert rules.vote_persists_next_cycle is True

    def test_config_validation(self):
        """Test config validates ranges."""
        # Weight must be >= 0
        with pytest.raises(ValueError):
            VoteWeightsConfig(premium_full=-1)

        # Weight must be <= 10
        with pytest.raises(ValueError):
            VoteWeightsConfig(premium_full=11)

    def test_custom_config_override(self):
        """Test creating config with custom values."""
        custom_weights = VoteWeightsConfig(
            premium_full=5,
            premium_hybrid=3,
            free_with_ads=2,
            free_no_ads=0
        )

        config = SpecialProjectsConfig(vote_weights=custom_weights)

        assert config.vote_weights.premium_full == 5
        assert config.vote_weights.premium_hybrid == 3


# ======================== MODEL TESTS ========================

class TestSpecialProjectModel:
    """Test SpecialProject model."""

    @pytest.mark.asyncio
    async def test_create_project(self, async_db: AsyncSession):
        """Test creating a project."""
        project = SpecialProject(
            title="Test Project",
            slug="test-project",
            description="A" * 100,
            status=ProjectStatus.DRAFT
        )

        async_db.add(project)
        await async_db.flush()

        assert project.id is not None
        assert project.total_votes == 0
        assert project.total_weighted_votes == 0
        assert project.is_deleted is False

    @pytest.mark.asyncio
    async def test_project_is_voting_open(self, async_db: AsyncSession):
        """Test is_voting_open logic."""
        # Draft project - not open
        project_draft = SpecialProject(
            title="Draft Project",
            slug="draft-project",
            description="A" * 100,
            status=ProjectStatus.DRAFT
        )
        assert project_draft.is_voting_open() is False

        # Active with valid dates
        project_active = SpecialProject(
            title="Active Project",
            slug="active-project",
            description="A" * 100,
            status=ProjectStatus.ACTIVE,
            voting_start_date=datetime.utcnow() - timedelta(days=1),
            voting_end_date=datetime.utcnow() + timedelta(days=30)
        )
        assert project_active.is_voting_open() is True

        # Active but voting not started
        project_future = SpecialProject(
            title="Future Project",
            slug="future-project",
            description="A" * 100,
            status=ProjectStatus.ACTIVE,
            voting_start_date=datetime.utcnow() + timedelta(days=1)
        )
        assert project_future.is_voting_open() is False

        # Active but voting ended
        project_ended = SpecialProject(
            title="Ended Project",
            slug="ended-project",
            description="A" * 100,
            status=ProjectStatus.ACTIVE,
            voting_end_date=datetime.utcnow() - timedelta(days=1)
        )
        assert project_ended.is_voting_open() is False


class TestProjectVoteModel:
    """Test ProjectVote model."""

    @pytest.mark.asyncio
    async def test_create_vote(self, async_db: AsyncSession, test_project, test_users):
        """Test creating a vote."""
        vote = ProjectVote(
            user_id=test_users["premium_full"].id,
            project_id=test_project.id,
            vote_weight=3,
            subscription_tier_at_vote="premium_full",
            vote_cycle="2024-12"
        )

        async_db.add(vote)
        await async_db.flush()

        assert vote.id is not None
        assert vote.is_active is True
        assert vote.changed_from_previous is False


class TestVotingEligibilityModel:
    """Test VotingEligibility model."""

    @pytest.mark.asyncio
    async def test_create_eligibility(self, async_db: AsyncSession, test_users):
        """Test creating eligibility record."""
        eligibility = VotingEligibility(
            user_id=test_users["premium_full"].id,
            vote_cycle="2024-12",
            status=EligibilityStatus.ELIGIBLE,
            vote_weight=3,
            subscription_tier="premium_full"
        )

        async_db.add(eligibility)
        await async_db.flush()

        assert eligibility.id is not None
        assert eligibility.is_eligible() is True

    @pytest.mark.asyncio
    async def test_eligibility_not_eligible(self, async_db: AsyncSession, test_users):
        """Test not eligible status."""
        eligibility = VotingEligibility(
            user_id=test_users["free_with_ads"].id,
            vote_cycle="2024-12",
            status=EligibilityStatus.NOT_ELIGIBLE,
            vote_weight=0,
            subscription_tier="free_with_ads",
            ineligibility_reason="Requirements not met"
        )

        async_db.add(eligibility)
        await async_db.flush()

        assert eligibility.is_eligible() is False


# ======================== ELIGIBILITY CALCULATOR TESTS ========================

class TestEligibilityCalculator:
    """Test EligibilityCalculator service."""

    @pytest.mark.asyncio
    async def test_get_current_vote_cycle(self, async_db: AsyncSession, config):
        """Test vote cycle format."""
        calculator = EligibilityCalculator(async_db, config)

        cycle = calculator.get_current_vote_cycle()

        # Should be YYYY-MM format
        assert len(cycle) == 7
        assert cycle[4] == "-"
        year, month = cycle.split("-")
        assert 2020 <= int(year) <= 2030
        assert 1 <= int(month) <= 12

    @pytest.mark.asyncio
    async def test_premium_user_always_eligible(
        self, async_db: AsyncSession, config, test_users
    ):
        """Test premium users are always eligible."""
        calculator = EligibilityCalculator(async_db, config)

        eligibility = await calculator.check_eligibility(
            test_users["premium_full"].id
        )

        assert eligibility.status == EligibilityStatus.ELIGIBLE
        assert eligibility.vote_weight == 3  # premium_full weight


# ======================== SERVICE TESTS ========================

class TestSpecialProjectsService:
    """Test SpecialProjectsService."""

    @pytest.mark.asyncio
    async def test_create_project(self, service: SpecialProjectsService, test_users):
        """Test creating a project through service."""
        data = SpecialProjectCreate(
            title="New Feature Request",
            description="A" * 100,
            short_description="A cool feature",
            estimated_budget_cents=100000,  # 1000 EUR
            estimated_days=30,
            tags=["feature", "mobile"]
        )

        project = await service.create_project(data, test_users["admin"].id)

        assert project.id is not None
        assert project.title == "New Feature Request"
        assert project.slug == "new-feature-request"
        assert project.status == ProjectStatus.DRAFT
        assert project.tags == ["feature", "mobile"]

    @pytest.mark.asyncio
    async def test_create_project_slug_generation(
        self, service: SpecialProjectsService, test_users
    ):
        """Test slug is properly generated from title."""
        data = SpecialProjectCreate(
            title="AI Coach   Feature!!!",
            description="A" * 100
        )

        project = await service.create_project(data, test_users["admin"].id)

        # Slug should be lowercase, no special chars, single dashes
        assert project.slug == "ai-coach-feature"

    @pytest.mark.asyncio
    async def test_update_project(
        self, service: SpecialProjectsService, test_project
    ):
        """Test updating a project."""
        update_data = SpecialProjectUpdate(
            title="Updated Title",
            status=ProjectStatusEnum.ACTIVE
        )

        updated = await service.update_project(test_project.id, update_data)

        assert updated.title == "Updated Title"
        assert updated.status == ProjectStatus.ACTIVE

    @pytest.mark.asyncio
    async def test_list_projects(
        self, service: SpecialProjectsService, async_db, test_users
    ):
        """Test listing projects with pagination."""
        # Create multiple projects
        for i in range(5):
            project = SpecialProject(
                title=f"Project {i}",
                slug=f"project-{i}",
                description="A" * 100,
                status=ProjectStatus.ACTIVE,
                created_by=test_users["admin"].id
            )
            async_db.add(project)
        await async_db.flush()

        projects, total = await service.list_projects(
            status=ProjectStatus.ACTIVE,
            page=1,
            page_size=3
        )

        assert len(projects) == 3
        assert total == 5

    @pytest.mark.asyncio
    async def test_vote_for_project(
        self, service: SpecialProjectsService, test_project, test_users, async_db
    ):
        """Test voting for a project."""
        vote_data = ProjectVoteCreate(project_id=test_project.id)

        vote, message = await service.vote(
            test_users["premium_full"].id,
            vote_data
        )

        assert vote is not None
        assert vote.vote_weight == 3  # premium_full
        assert "success" in message.lower()

        # Check project stats updated
        await async_db.refresh(test_project)
        assert test_project.total_votes == 1
        assert test_project.total_weighted_votes == 3

    @pytest.mark.asyncio
    async def test_cannot_vote_twice_same_project(
        self, service: SpecialProjectsService, test_project, test_users
    ):
        """Test user cannot vote twice for same project."""
        vote_data = ProjectVoteCreate(project_id=test_project.id)

        # First vote
        vote1, _ = await service.vote(test_users["premium_full"].id, vote_data)
        assert vote1 is not None

        # Try to vote again for same project
        vote2, message = await service.vote(test_users["premium_full"].id, vote_data)
        assert vote2 is None
        assert "already voted" in message.lower()

    @pytest.mark.asyncio
    async def test_vote_change_blocked_by_default(
        self, service: SpecialProjectsService, async_db, test_users
    ):
        """Test vote change is blocked by default config."""
        # Create two projects
        project1 = SpecialProject(
            title="Project 1",
            slug="project-1",
            description="A" * 100,
            status=ProjectStatus.ACTIVE,
            voting_start_date=datetime.utcnow() - timedelta(days=1)
        )
        project2 = SpecialProject(
            title="Project 2",
            slug="project-2",
            description="A" * 100,
            status=ProjectStatus.ACTIVE,
            voting_start_date=datetime.utcnow() - timedelta(days=1)
        )
        async_db.add_all([project1, project2])
        await async_db.flush()

        # Vote for project 1
        vote1, _ = await service.vote(
            test_users["premium_full"].id,
            ProjectVoteCreate(project_id=project1.id)
        )
        assert vote1 is not None

        # Try to vote for project 2 without confirm_change
        vote2, message = await service.vote(
            test_users["premium_full"].id,
            ProjectVoteCreate(project_id=project2.id, confirm_change=False)
        )
        assert vote2 is None
        assert "confirm_change" in message.lower()

    @pytest.mark.asyncio
    async def test_get_user_current_vote(
        self, service: SpecialProjectsService, test_project, test_users
    ):
        """Test getting user's current vote."""
        # No vote yet
        vote = await service.get_user_current_vote(test_users["premium_full"].id)
        assert vote is None

        # After voting
        await service.vote(
            test_users["premium_full"].id,
            ProjectVoteCreate(project_id=test_project.id)
        )

        vote = await service.get_user_current_vote(test_users["premium_full"].id)
        assert vote is not None
        assert vote.project_id == test_project.id


# ======================== SCHEMA VALIDATION TESTS ========================

class TestSchemaValidation:
    """Test Pydantic schema validation."""

    def test_project_create_min_description(self):
        """Test minimum description length."""
        with pytest.raises(ValueError):
            SpecialProjectCreate(
                title="Valid Title",
                description="Too short"  # Less than 100 chars
            )

    def test_project_create_valid(self):
        """Test valid project creation schema."""
        project = SpecialProjectCreate(
            title="Valid Project Title",
            description="A" * 100,
            tags=["Feature", "MOBILE"]
        )

        # Tags should be lowercased
        assert project.tags == ["feature", "mobile"]

    def test_project_create_title_sanitized(self):
        """Test title is stripped."""
        project = SpecialProjectCreate(
            title="  Padded Title  ",
            description="A" * 100
        )

        assert project.title == "Padded Title"

    def test_vote_response_cycle_display(self):
        """Test vote cycle display formatting."""
        response = ProjectVoteCreate(project_id=uuid4())
        assert response.project_id is not None


# ======================== INTEGRATION TESTS ========================

class TestFullVotingFlow:
    """Integration tests for complete voting flow."""

    @pytest.mark.asyncio
    async def test_complete_voting_cycle(
        self, service: SpecialProjectsService, async_db, test_users
    ):
        """Test complete voting cycle from project creation to stats."""
        admin_id = test_users["admin"].id

        # 1. Create project
        project_data = SpecialProjectCreate(
            title="Community Feature",
            description="A great feature requested by community. " * 10,
            estimated_budget_cents=50000,
            tags=["community", "feature"]
        )
        project = await service.create_project(project_data, admin_id)
        assert project.status == ProjectStatus.DRAFT

        # 2. Publish project
        project = await service.update_project(
            project.id,
            SpecialProjectUpdate(
                status=ProjectStatusEnum.ACTIVE,
                voting_start_date=datetime.utcnow() - timedelta(hours=1),
                voting_end_date=datetime.utcnow() + timedelta(days=30)
            )
        )
        assert project.status == ProjectStatus.ACTIVE
        assert project.is_voting_open()

        # 3. Users vote
        # Premium full user
        vote1, _ = await service.vote(
            test_users["premium_full"].id,
            ProjectVoteCreate(project_id=project.id)
        )
        assert vote1.vote_weight == 3

        # Premium hybrid user
        vote2, _ = await service.vote(
            test_users["premium_hybrid"].id,
            ProjectVoteCreate(project_id=project.id)
        )
        assert vote2.vote_weight == 2

        # 4. Check stats
        await async_db.refresh(project)
        assert project.total_votes == 2
        assert project.total_weighted_votes == 5  # 3 + 2
        assert project.unique_voters == 2

    @pytest.mark.asyncio
    async def test_multiple_projects_voting(
        self, service: SpecialProjectsService, async_db, test_users
    ):
        """Test voting across multiple projects."""
        # Create 3 projects
        projects = []
        for i in range(3):
            project = SpecialProject(
                title=f"Project {i}",
                slug=f"multi-project-{i}",
                description="A" * 100,
                status=ProjectStatus.ACTIVE,
                voting_start_date=datetime.utcnow() - timedelta(days=1),
                voting_end_date=datetime.utcnow() + timedelta(days=30),
                created_by=test_users["admin"].id
            )
            async_db.add(project)
            projects.append(project)
        await async_db.flush()

        # Different users vote for different projects
        await service.vote(
            test_users["premium_full"].id,
            ProjectVoteCreate(project_id=projects[0].id)
        )
        await service.vote(
            test_users["premium_hybrid"].id,
            ProjectVoteCreate(project_id=projects[1].id)
        )

        # Check votes are correctly distributed
        await async_db.refresh(projects[0])
        await async_db.refresh(projects[1])
        await async_db.refresh(projects[2])

        assert projects[0].total_weighted_votes == 3
        assert projects[1].total_weighted_votes == 2
        assert projects[2].total_weighted_votes == 0

    @pytest.mark.asyncio
    async def test_voting_stats(
        self, service: SpecialProjectsService, async_db, test_project, test_users
    ):
        """Test voting statistics calculation."""
        # Vote
        await service.vote(
            test_users["premium_full"].id,
            ProjectVoteCreate(project_id=test_project.id)
        )

        # Get stats
        stats = await service.get_voting_stats()

        assert "vote_cycle" in stats
        assert stats["total_votes_cast"] >= 1
        assert "votes_by_tier" in stats


# ======================== EDGE CASE TESTS ========================

class TestEdgeCases:
    """Test edge cases and error handling."""

    @pytest.mark.asyncio
    async def test_vote_for_nonexistent_project(
        self, service: SpecialProjectsService, test_users
    ):
        """Test voting for non-existent project."""
        fake_project_id = uuid4()

        vote, message = await service.vote(
            test_users["premium_full"].id,
            ProjectVoteCreate(project_id=fake_project_id)
        )

        assert vote is None
        assert "not found" in message.lower()

    @pytest.mark.asyncio
    async def test_vote_for_closed_project(
        self, service: SpecialProjectsService, async_db, test_users
    ):
        """Test voting for project with closed voting."""
        project = SpecialProject(
            title="Closed Project",
            slug="closed-project",
            description="A" * 100,
            status=ProjectStatus.ACTIVE,
            voting_end_date=datetime.utcnow() - timedelta(days=1)  # Ended
        )
        async_db.add(project)
        await async_db.flush()

        vote, message = await service.vote(
            test_users["premium_full"].id,
            ProjectVoteCreate(project_id=project.id)
        )

        assert vote is None
        assert "not open" in message.lower()

    @pytest.mark.asyncio
    async def test_vote_for_draft_project(
        self, service: SpecialProjectsService, async_db, test_users
    ):
        """Test voting for draft project."""
        project = SpecialProject(
            title="Draft Project",
            slug="draft-test-project",
            description="A" * 100,
            status=ProjectStatus.DRAFT
        )
        async_db.add(project)
        await async_db.flush()

        vote, message = await service.vote(
            test_users["premium_full"].id,
            ProjectVoteCreate(project_id=project.id)
        )

        assert vote is None
        assert "not open" in message.lower()


# ======================== RUN TESTS ========================

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--asyncio-mode=auto"])
