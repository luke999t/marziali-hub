"""
================================================================================
    CURRICULUM SERVICES - Exam Analysis & Access Management
================================================================================

AI_MODULE: Curriculum Services
AI_DESCRIPTION: AI-powered exam evaluation and access control
AI_BUSINESS: Core differentiation via AI feedback quality

SERVICES:
    ExamAnalyzer    - AI-powered exam video analysis
    AccessManager   - Invite codes and access control

================================================================================
"""

from .exam_analyzer import ExamAnalyzer
from .access_manager import AccessManager

__all__ = [
    "ExamAnalyzer",
    "AccessManager",
]
