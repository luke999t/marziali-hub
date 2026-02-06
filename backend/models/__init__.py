"""
AI_MODULE: Models Export
AI_DESCRIPTION: Export centralizzato tutti i models
AI_TEACHING: Import pattern per ORM models
"""

import uuid
import json
from sqlalchemy import TypeDecorator, String, Text
from sqlalchemy.dialects.postgresql import UUID as PG_UUID, ARRAY as PG_ARRAY, JSONB as PG_JSONB


class GUID(TypeDecorator):
    """Platform-independent GUID type.
    Uses PostgreSQL's UUID type, otherwise uses String(36).
    """
    impl = String(36)
    cache_ok = True

    def load_dialect_impl(self, dialect):
        if dialect.name == 'postgresql':
            return dialect.type_descriptor(PG_UUID(as_uuid=True))
        else:
            return dialect.type_descriptor(String(36))

    def process_bind_param(self, value, dialect):
        if value is None:
            return value
        elif dialect.name == 'postgresql':
            return str(value) if isinstance(value, uuid.UUID) else value
        else:
            return str(value) if isinstance(value, uuid.UUID) else value

    def process_result_value(self, value, dialect):
        if value is None:
            return value
        else:
            if not isinstance(value, uuid.UUID):
                value = uuid.UUID(value)
            return value


class ArrayType(TypeDecorator):
    """Platform-independent ARRAY type.
    Uses PostgreSQL's ARRAY type, otherwise uses JSON Text field.
    """
    impl = Text
    cache_ok = True

    def __init__(self, item_type=String, *args, **kwargs):
        self.item_type = item_type
        super().__init__(*args, **kwargs)

    def load_dialect_impl(self, dialect):
        if dialect.name == 'postgresql':
            return dialect.type_descriptor(PG_ARRAY(self.item_type))
        else:
            return dialect.type_descriptor(Text())

    def process_bind_param(self, value, dialect):
        if value is None:
            return value
        elif dialect.name == 'postgresql':
            return value
        else:
            return json.dumps(value)

    def process_result_value(self, value, dialect):
        if value is None:
            return value
        elif dialect.name == 'postgresql':
            return value
        else:
            return json.loads(value) if isinstance(value, str) else value


class JSONBType(TypeDecorator):
    """Platform-independent JSONB type.
    Uses PostgreSQL's JSONB type, otherwise uses JSON Text field.
    """
    impl = Text
    cache_ok = True

    def load_dialect_impl(self, dialect):
        if dialect.name == 'postgresql':
            return dialect.type_descriptor(PG_JSONB())
        else:
            return dialect.type_descriptor(Text())

    def process_bind_param(self, value, dialect):
        if value is None:
            return value
        elif dialect.name == 'postgresql':
            return value
        else:
            return json.dumps(value) if not isinstance(value, str) else value

    def process_result_value(self, value, dialect):
        if value is None:
            return value
        elif dialect.name == 'postgresql':
            return value
        else:
            return json.loads(value) if isinstance(value, str) else value


from .user import (
    User,
    UserTier,
    SubscriptionHistory,
    SubscriptionStatus,
    ViewingHistory,
    Favorite,
    Purchase
)

from .video import (
    Video,
    VideoStatus,
    VideoCategory,
    Difficulty,
    Course,
    CourseItem,
    LiveEvent,
    LiveEventType,
    LiveEventStatus,
    LibraryItem
)

from .ads import (
    AdsSession,
    AdsBatchType,
    AdsSessionStatus,
    AdInventory,
    BlockchainBatch,
    ConsensusStatus,
    StoreNode,
    NodeValidation,
    PauseAd,
    PauseAdImpression
)

# New models - Import order matters for relationships!
from .maestro import (
    Maestro,
    MaestroStatus,
    BackgroundCheckStatus,
    Discipline,
    ASD,
    ASDMember
)

from .donation import (
    StellineWallet,
    Donation,
    DonationBlockchainBatch,
    WithdrawalRequest,
    WithdrawalStatus,
    PayoutMethod,
    WalletTransaction,
    WalletTransactionType,
    FiscalReceiptType
)

from .communication import (
    Message,
    MessageAttachmentType,
    CorrectionRequest,
    CorrectionRequestStatus,
    TranslationDataset,
    TranslationProcessingStatus,
    GlossaryTerm,
    LiveChatMessage
)

from .live_minor import (
    Minor,
    AgeBracket,
    ConsentStatus,
    ParentalApproval,
    ActivityLog
)

from .curriculum import (
    Curriculum,
    CurriculumLevel,
    CurriculumEnrollment,
    LevelProgress,
    ExamSubmission,
    Certificate,
    CurriculumInviteCode,
    CurriculumDiscipline,
    CurriculumOwnerType,
    CurriculumVisibility,
    CurriculumPricingModel,
    ExamType,
    LevelStatus,
    EnrollmentAccessType,
    SubscriptionType,
    ExamStatus,
    CertificateIssuerType,
    curriculum_level_courses,
    curriculum_level_videos
)

from .ingest_project import (
    IngestProject,
    IngestBatch,
    IngestAsset,
    IngestMixVersion,
    BatchStatus,
    AssetType,
    AssetStatus,
    InputChannel
)

from .user_video import UserVideo

from .notification import (
    Notification,
    NotificationType,
    NotificationPriority,
    DeviceToken,
    DeviceType,
    NotificationPreference
)

from .download import (
    Download,
    DownloadLimit,
    DownloadStatus,
    DownloadQuality,
    get_estimated_file_size
)

from .analytics import (
    AnalyticsDaily,
    SystemHealthLog
)

from .avatar import (
    Avatar,
    AvatarStyle,
    AvatarRigType,
    AvatarLicenseType
)

from .content_type import ContentType

from .video_section import VideoSection

__all__ = [
    # Custom types
    "GUID",
    "ArrayType",
    "JSONBType",

    # User models
    "User",
    "UserTier",
    "SubscriptionHistory",
    "SubscriptionStatus",
    "ViewingHistory",
    "Favorite",
    "Purchase",

    # Video models
    "Video",
    "VideoStatus",
    "VideoCategory",
    "Difficulty",
    "Course",
    "CourseItem",
    "LiveEvent",
    "LiveEventType",
    "LiveEventStatus",
    "LibraryItem",

    # Ads & Blockchain models
    "AdsSession",
    "AdsBatchType",
    "AdsSessionStatus",
    "AdInventory",
    "BlockchainBatch",
    "ConsensusStatus",
    "StoreNode",
    "NodeValidation",
    "PauseAd",
    "PauseAdImpression",

    # Maestro & ASD models
    "Maestro",
    "MaestroStatus",
    "BackgroundCheckStatus",
    "Discipline",
    "ASD",
    "ASDMember",

    # Donation & Wallet models
    "StellineWallet",
    "Donation",
    "DonationBlockchainBatch",
    "WithdrawalRequest",
    "WithdrawalStatus",
    "PayoutMethod",
    "WalletTransaction",
    "WalletTransactionType",
    "FiscalReceiptType",

    # Communication models
    "Message",
    "MessageAttachmentType",
    "CorrectionRequest",
    "CorrectionRequestStatus",
    "TranslationDataset",
    "TranslationProcessingStatus",
    "GlossaryTerm",
    "LiveChatMessage",

    # Minor & COPPA models
    "Minor",
    "AgeBracket",
    "ConsentStatus",
    "ParentalApproval",
    "ActivityLog",

    # Curriculum models
    "Curriculum",
    "CurriculumLevel",
    "CurriculumEnrollment",
    "LevelProgress",
    "ExamSubmission",
    "Certificate",
    "CurriculumInviteCode",
    "CurriculumDiscipline",
    "CurriculumOwnerType",
    "CurriculumVisibility",
    "CurriculumPricingModel",
    "ExamType",
    "LevelStatus",
    "EnrollmentAccessType",
    "SubscriptionType",
    "ExamStatus",
    "CertificateIssuerType",
    "curriculum_level_courses",
    "curriculum_level_videos",

    # Ingest Project models
    "IngestProject",
    "IngestBatch",
    "IngestAsset",
    "IngestMixVersion",
    "BatchStatus",
    "AssetType",
    "AssetStatus",
    "InputChannel",

    # UserVideo
    "UserVideo",

    # Notification models
    "Notification",
    "NotificationType",
    "NotificationPriority",
    "DeviceToken",
    "DeviceType",
    "NotificationPreference",

    # Download models
    "Download",
    "DownloadLimit",
    "DownloadStatus",
    "DownloadQuality",
    "get_estimated_file_size",

    # Analytics models
    "AnalyticsDaily",
    "SystemHealthLog",

    # Avatar models
    "Avatar",
    "AvatarStyle",
    "AvatarRigType",
    "AvatarLicenseType",

    # Content Classification models
    "ContentType",
    "VideoSection",
]
