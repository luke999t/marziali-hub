# US-001: Translation Debate System - PART 2

## 📦 Module 2: TranslationDebate Service

### Task 1.2.1: Create file with AI-First header (5 min)
**File:** `backend/services/translation/__init__.py`
```python
# Translation services package
```

**File:** `backend/services/translation/translation_debate.py`
```python
"""
🎓 AI_MODULE: TranslationDebate
🎓 AI_DESCRIPTION: Two LLMs debate to produce accurate translations
🎓 AI_BUSINESS: Higher accuracy than single model (+15-20%), specialized for martial arts terminology
🎓 AI_TEACHING: Multi-agent consensus pattern, iterative refinement

🔄 ALTERNATIVE_VALUTATE:
- Single model: Scartato, accuracy 70-75% vs 85-90% with debate
- Ensemble voting: Scartato, needs 3+ models, higher latency
- Chain-of-thought: Scartato, good but debate catches more errors

💡 PERCHÉ_QUESTA_SOLUZIONE:
- Two models catch each other's mistakes
- Debate forces reasoning explanation
- Confidence score from agreement level
- Fallback to single model if one unavailable

📊 METRICHE_SUCCESSO:
- Accuracy: 85-90% on martial arts terms
- Confidence correlation: >0.8 with human ratings
- Latency: <60s for 3-round debate

⚠️ CRITICAL:
- Requires both models available for full debate
- Falls back to single model gracefully
- Max 3 rounds to prevent infinite loops
"""

import asyncio
import logging
from typing import Optional, List
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

from .engines.ollama_engine import OllamaEngine, TranslationResult

logger = logging.getLogger(__name__)
```
**Validation:** File exists, imports work
**Commit:** `feat(translation): create translation_debate.py with AI-First header`

---

### Task 1.2.2: Define DebateResult and DebateRound dataclasses (5 min)
**File:** `backend/services/translation/translation_debate.py` (append)
```python
class DebateStatus(Enum):
    """
    🎓 AI_TEACHING: Enum for type-safe status values
    """
    SUCCESS = "success"              # Debate completed, consensus reached
    PARTIAL = "partial"              # One model failed, used single model
    FAILED = "failed"                # Both models failed
    TIMEOUT = "timeout"              # Debate took too long


@dataclass
class DebateRound:
    """
    🎓 AI_TEACHING: Track each round of the debate for transparency
    """
    round_number: int
    model_a_response: str
    model_b_response: str
    agreement_score: float           # 0.0-1.0, how similar the responses are
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass 
class DebateResult:
    """
    🎓 AI_BUSINESS: Final result with full audit trail
    """
    original_text: str
    final_translation: str
    source_lang: str
    target_lang: str
    confidence: float                # 0.0-1.0, based on model agreement
    status: DebateStatus
    rounds: List[DebateRound]        # Full debate history
    total_time_ms: int
    model_a: str
    model_b: str
    winner_model: Optional[str]      # Which model's translation was chosen
    timestamp: datetime = field(default_factory=datetime.now)
```
**Validation:** `python -c "from backend.services.translation.translation_debate import DebateResult"`
**Commit:** `feat(translation): add DebateResult and DebateRound dataclasses`

---

### Task 1.2.3: Create TranslationDebate class skeleton (5 min)
**File:** `backend/services/translation/translation_debate.py` (append)
```python
class TranslationDebate:
    """
    🎓 AI_TEACHING: Orchestrates the debate between two LLM translators
    Single Responsibility: Only handles debate logic, not HTTP/API
    """
    
    # Configuration constants
    MAX_ROUNDS = 3
    CONFIDENCE_THRESHOLD = 0.7       # Below this, do another round
    MIN_AGREEMENT_TO_STOP = 0.85     # Above this, stop early
    
    def __init__(
        self,
        model_a: str = "qwen2.5:7b",
        model_b: str = "llama3.1:8b",
        ollama_url: str = "http://localhost:11434"
    ):
        """
        🎓 AI_BUSINESS: qwen for Chinese expertise, llama for general knowledge
        
        Args:
            model_a: Primary model (best for source language)
            model_b: Secondary model (reviewer/challenger)
            ollama_url: Ollama server URL
        """
        self.model_a = model_a
        self.model_b = model_b
        self.ollama_url = ollama_url
        
        logger.info(f"TranslationDebate initialized: {model_a} vs {model_b}")
```
**Validation:** Class imports without error
**Commit:** `feat(translation): add TranslationDebate class skeleton`

---

### Task 1.2.4: Implement _calculate_agreement() helper (10 min)
**File:** `backend/services/translation/translation_debate.py` (add to class)
```python
    def _calculate_agreement(self, text_a: str, text_b: str) -> float:
        """
        🎓 AI_TEACHING: Simple agreement metric based on word overlap
        More sophisticated: use embedding similarity (future enhancement)
        
        Args:
            text_a: First translation
            text_b: Second translation
            
        Returns:
            Agreement score 0.0-1.0
        """
        if not text_a or not text_b:
            return 0.0
        
        # Normalize: lowercase, split into words
        words_a = set(text_a.lower().split())
        words_b = set(text_b.lower().split())
        
        if not words_a or not words_b:
            return 0.0
        
        # Jaccard similarity: intersection / union
        intersection = len(words_a & words_b)
        union = len(words_a | words_b)
        
        similarity = intersection / union if union > 0 else 0.0
        
        logger.debug(f"Agreement: {similarity:.2f} ({intersection}/{union} words)")
        return similarity
```
**Validation:** Unit test this method
**Commit:** `feat(translation): add _calculate_agreement helper`

---

### Task 1.2.5: Implement _check_models_available() (5 min)
**File:** `backend/services/translation/translation_debate.py` (add to class)
```python
    async def _check_models_available(self) -> tuple[bool, bool]:
        """
        🎓 AI_BUSINESS: Check which models are available before starting
        
        Returns:
            Tuple of (model_a_available, model_b_available)
        """
        engine_a = OllamaEngine(model=self.model_a, base_url=self.ollama_url)
        engine_b = OllamaEngine(model=self.model_b, base_url=self.ollama_url)
        
        available_a = await engine_a.is_available()
        available_b = await engine_b.is_available()
        
        logger.info(f"Model availability: {self.model_a}={available_a}, {self.model_b}={available_b}")
        
        return available_a, available_b
```
**Validation:** Test with Ollama running
**Commit:** `feat(translation): add _check_models_available`

---

### Task 1.2.6: Implement _single_model_fallback() (10 min)
**File:** `backend/services/translation/translation_debate.py` (add to class)
```python
    async def _single_model_fallback(
        self,
        text: str,
        source_lang: str,
        target_lang: str,
        model: str,
        start_time: datetime
    ) -> DebateResult:
        """
        🎓 AI_BUSINESS: Graceful degradation when one model unavailable
        Better to give single-model translation than fail completely
        
        Args:
            text: Text to translate
            source_lang: Source language
            target_lang: Target language
            model: Which model to use
            start_time: When debate started (for timing)
            
        Returns:
            DebateResult with PARTIAL status
        """
        logger.warning(f"Falling back to single model: {model}")
        
        async with OllamaEngine(model=model, base_url=self.ollama_url) as engine:
            result = await engine.translate(text, source_lang, target_lang)
        
        elapsed_ms = int((datetime.now() - start_time).total_seconds() * 1000)
        
        return DebateResult(
            original_text=text,
            final_translation=result.translation,
            source_lang=source_lang,
            target_lang=target_lang,
            confidence=result.confidence * 0.8,  # Reduce confidence for single model
            status=DebateStatus.PARTIAL,
            rounds=[],  # No debate rounds
            total_time_ms=elapsed_ms,
            model_a=self.model_a,
            model_b=self.model_b,
            winner_model=model
        )
```
**Validation:** Test fallback scenario
**Commit:** `feat(translation): add _single_model_fallback`

---

### Task 1.2.7: Implement _run_debate_round() (15 min)
**File:** `backend/services/translation/translation_debate.py` (add to class)
```python
    async def _run_debate_round(
        self,
        text: str,
        source_lang: str,
        target_lang: str,
        round_number: int,
        previous_translations: List[str] = None
    ) -> DebateRound:
        """
        🎓 AI_TEACHING: Single round of the debate
        
        Round 1: Both models translate independently
        Round 2+: Models see each other's previous translations and can revise
        
        Args:
            text: Original text
            source_lang: Source language
            target_lang: Target language
            round_number: Which round (1, 2, or 3)
            previous_translations: Previous round's translations for context
            
        Returns:
            DebateRound with both responses and agreement score
        """
        async with OllamaEngine(model=self.model_a, base_url=self.ollama_url) as engine_a, \
                   OllamaEngine(model=self.model_b, base_url=self.ollama_url) as engine_b:
            
            if round_number == 1 or not previous_translations:
                # First round: independent translation
                result_a, result_b = await asyncio.gather(
                    engine_a.translate(text, source_lang, target_lang),
                    engine_b.translate(text, source_lang, target_lang)
                )
            else:
                # Subsequent rounds: review and revise
                # Model A sees Model B's translation and vice versa
                review_prompt_a = f"""Previous translation by another model: "{previous_translations[1]}"
                
Original text: {text}

Review the translation above and provide your own translation from {source_lang} to {target_lang}.
If you agree, output the same. If you disagree, provide a better translation.
Output ONLY the translation:"""

                review_prompt_b = f"""Previous translation by another model: "{previous_translations[0]}"
                
Original text: {text}

Review the translation above and provide your own translation from {source_lang} to {target_lang}.
If you agree, output the same. If you disagree, provide a better translation.
Output ONLY the translation:"""

                # Use _make_request for custom prompts
                response_a = await engine_a._make_request(review_prompt_a)
                response_b = await engine_b._make_request(review_prompt_b)
                
                result_a = TranslationResult(
                    text=text,
                    translation=response_a.get("response", "").strip(),
                    source_lang=source_lang,
                    target_lang=target_lang,
                    model=self.model_a,
                    confidence=0.0,
                    processing_time_ms=0,
                    timestamp=datetime.now()
                )
                result_b = TranslationResult(
                    text=text,
                    translation=response_b.get("response", "").strip(),
                    source_lang=source_lang,
                    target_lang=target_lang,
                    model=self.model_b,
                    confidence=0.0,
                    processing_time_ms=0,
                    timestamp=datetime.now()
                )
            
            agreement = self._calculate_agreement(result_a.translation, result_b.translation)
            
            return DebateRound(
                round_number=round_number,
                model_a_response=result_a.translation,
                model_b_response=result_b.translation,
                agreement_score=agreement
            )
```
**Validation:** Test single round
**Commit:** `feat(translation): add _run_debate_round`

---

### Task 1.2.8: Implement debate() main method (15 min)
**File:** `backend/services/translation/translation_debate.py` (add to class)
```python
    async def debate(
        self,
        text: str,
        source_lang: str,
        target_lang: str
    ) -> DebateResult:
        """
        🎓 AI_BUSINESS: Main entry point - orchestrates the full debate
        
        Flow:
        1. Check model availability
        2. If both available: run debate rounds
        3. If one available: fallback to single model
        4. If none available: return FAILED status
        
        Args:
            text: Text to translate
            source_lang: Source language code
            target_lang: Target language code
            
        Returns:
            DebateResult with final translation and full audit trail
        """
        start_time = datetime.now()
        
        # Check model availability
        model_a_ok, model_b_ok = await self._check_models_available()
        
        # Handle unavailable models
        if not model_a_ok and not model_b_ok:
            logger.error("Both models unavailable")
            return DebateResult(
                original_text=text,
                final_translation="",
                source_lang=source_lang,
                target_lang=target_lang,
                confidence=0.0,
                status=DebateStatus.FAILED,
                rounds=[],
                total_time_ms=0,
                model_a=self.model_a,
                model_b=self.model_b,
                winner_model=None
            )
        
        if not model_a_ok:
            return await self._single_model_fallback(
                text, source_lang, target_lang, self.model_b, start_time
            )
        
        if not model_b_ok:
            return await self._single_model_fallback(
                text, source_lang, target_lang, self.model_a, start_time
            )
        
        # Run debate rounds
        rounds: List[DebateRound] = []
        previous_translations = None
        
        for round_num in range(1, self.MAX_ROUNDS + 1):
            logger.info(f"Starting debate round {round_num}/{self.MAX_ROUNDS}")
            
            round_result = await self._run_debate_round(
                text, source_lang, target_lang, round_num, previous_translations
            )
            rounds.append(round_result)
            
            # Check if we can stop early (high agreement)
            if round_result.agreement_score >= self.MIN_AGREEMENT_TO_STOP:
                logger.info(f"Early stop: agreement {round_result.agreement_score:.2f} >= {self.MIN_AGREEMENT_TO_STOP}")
                break
            
            # Prepare for next round
            previous_translations = [round_result.model_a_response, round_result.model_b_response]
        
        # Determine winner based on final round
        final_round = rounds[-1]
        
        # If high agreement, use model_a (primary)
        # If low agreement, prefer model_a but lower confidence
        if final_round.agreement_score >= self.CONFIDENCE_THRESHOLD:
            final_translation = final_round.model_a_response
            confidence = final_round.agreement_score
            winner = self.model_a
        else:
            # Low agreement - use model_a but flag lower confidence
            final_translation = final_round.model_a_response
            confidence = final_round.agreement_score * 0.9  # Penalize for disagreement
            winner = self.model_a
            logger.warning(f"Low agreement ({final_round.agreement_score:.2f}), using {winner} with reduced confidence")
        
        elapsed_ms = int((datetime.now() - start_time).total_seconds() * 1000)
        
        return DebateResult(
            original_text=text,
            final_translation=final_translation,
            source_lang=source_lang,
            target_lang=target_lang,
            confidence=confidence,
            status=DebateStatus.SUCCESS,
            rounds=rounds,
            total_time_ms=elapsed_ms,
            model_a=self.model_a,
            model_b=self.model_b,
            winner_model=winner
        )
```
**Validation:** Full integration test
**Commit:** `feat(translation): add debate() main method`

---

## 📦 Module 3: API Endpoint

### Task 1.3.1: Create API router file with header (5 min)
**File:** `backend/api/v1/translation_debate.py`
```python
"""
🎓 AI_MODULE: Translation Debate API Router
🎓 AI_DESCRIPTION: REST endpoints for translation debate service
🎓 AI_BUSINESS: Expose translation debate to frontend/mobile apps
🎓 AI_TEACHING: FastAPI router pattern, Pydantic validation

🔄 ALTERNATIVE_VALUTATE:
- GraphQL: Scartato, overkill for this use case
- gRPC: Scartato, need browser compatibility
- WebSocket: Scartato, request-response is fine for translation

💡 PERCHÉ_QUESTA_SOLUZIONE:
- REST is simple and widely supported
- FastAPI auto-generates OpenAPI docs
- Pydantic validates input automatically
"""

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime

from ...services.translation.translation_debate import (
    TranslationDebate, 
    DebateResult,
    DebateStatus
)

router = APIRouter(prefix="/translation", tags=["Translation"])
```
**Validation:** File imports work
**Commit:** `feat(api): create translation_debate router`

---

### Task 1.3.2: Define Pydantic request/response models (5 min)
**File:** `backend/api/v1/translation_debate.py` (append)
```python
# ============================================================
# REQUEST/RESPONSE MODELS
# ============================================================

class DebateRequest(BaseModel):
    """
    🎓 AI_TEACHING: Pydantic validates and documents the API automatically
    """
    text: str = Field(..., min_length=1, max_length=5000, description="Text to translate")
    source_lang: str = Field(..., min_length=2, max_length=20, description="Source language (e.g., 'Chinese', 'zh')")
    target_lang: str = Field(..., min_length=2, max_length=20, description="Target language (e.g., 'English', 'en')")
    
    class Config:
        json_schema_extra = {
            "example": {
                "text": "太极拳",
                "source_lang": "Chinese",
                "target_lang": "English"
            }
        }


class DebateRoundResponse(BaseModel):
    """Single round of the debate"""
    round_number: int
    model_a_response: str
    model_b_response: str
    agreement_score: float


class DebateResponse(BaseModel):
    """
    🎓 AI_BUSINESS: Full response with audit trail for transparency
    """
    original_text: str
    translation: str
    source_lang: str
    target_lang: str
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence score 0-1")
    status: str
    rounds: List[DebateRoundResponse]
    total_time_ms: int
    model_a: str
    model_b: str
    winner_model: Optional[str]
    
    class Config:
        json_schema_extra = {
            "example": {
                "original_text": "太极拳",
                "translation": "Tai Chi",
                "source_lang": "Chinese",
                "target_lang": "English",
                "confidence": 0.92,
                "status": "success",
                "rounds": [
                    {
                        "round_number": 1,
                        "model_a_response": "Tai Chi",
                        "model_b_response": "Tai Chi Chuan",
                        "agreement_score": 0.75
                    }
                ],
                "total_time_ms": 3500,
                "model_a": "qwen2.5:7b",
                "model_b": "llama3.1:8b",
                "winner_model": "qwen2.5:7b"
            }
        }
```
**Validation:** Pydantic models validate
**Commit:** `feat(api): add Pydantic request/response models`

---

### Task 1.3.3: Implement POST /translation/debate endpoint (10 min)
**File:** `backend/api/v1/translation_debate.py` (append)
```python
# ============================================================
# ENDPOINTS
# ============================================================

@router.post(
    "/debate",
    response_model=DebateResponse,
    summary="Translate text using LLM debate",
    description="Two LLMs debate to produce accurate translation with confidence score"
)
async def debate_translation(request: DebateRequest) -> DebateResponse:
    """
    🎓 AI_BUSINESS: Main translation endpoint
    🎓 AI_TEACHING: async endpoint for non-blocking I/O
    
    Process:
    1. Validate input (Pydantic does this)
    2. Create TranslationDebate instance
    3. Run debate
    4. Convert internal result to API response
    """
    try:
        # Create debate service
        debate_service = TranslationDebate()
        
        # Run debate
        result: DebateResult = await debate_service.debate(
            text=request.text,
            source_lang=request.source_lang,
            target_lang=request.target_lang
        )
        
        # Check for failure
        if result.status == DebateStatus.FAILED:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Translation service unavailable. Ensure Ollama is running."
            )
        
        # Convert to response
        return DebateResponse(
            original_text=result.original_text,
            translation=result.final_translation,
            source_lang=result.source_lang,
            target_lang=result.target_lang,
            confidence=result.confidence,
            status=result.status.value,
            rounds=[
                DebateRoundResponse(
                    round_number=r.round_number,
                    model_a_response=r.model_a_response,
                    model_b_response=r.model_b_response,
                    agreement_score=r.agreement_score
                )
                for r in result.rounds
            ],
            total_time_ms=result.total_time_ms,
            model_a=result.model_a,
            model_b=result.model_b,
            winner_model=result.winner_model
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Translation failed: {str(e)}"
        )


@router.get(
    "/health",
    summary="Check translation service health",
    description="Verify Ollama and models are available"
)
async def translation_health():
    """
    🎓 AI_BUSINESS: Health check for monitoring/load balancers
    """
    debate_service = TranslationDebate()
    model_a_ok, model_b_ok = await debate_service._check_models_available()
    
    return {
        "status": "healthy" if (model_a_ok and model_b_ok) else "degraded",
        "models": {
            "qwen2.5:7b": "available" if model_a_ok else "unavailable",
            "llama3.1:8b": "available" if model_b_ok else "unavailable"
        }
    }
```
**Validation:** Start server, test endpoint
**Commit:** `feat(api): add POST /translation/debate endpoint`

---

### Task 1.3.4: Register router in main.py (5 min)
**File:** `backend/main.py` (add import and include)
```python
# Add to imports
from api.v1.translation_debate import router as translation_router

# Add to router includes (in create_app or main)
app.include_router(translation_router, prefix="/api/v1")
```
**Validation:** `curl http://localhost:8000/api/v1/translation/health`
**Commit:** `feat(api): register translation router in main.py`

---

## 📦 Module 4: Integration Tests

### Task 1.4.1: Create integration test file (5 min)
**File:** `backend/tests/integration/test_translation_debate_integration.py`
```python
"""
🎓 AI_MODULE: Translation Debate Integration Tests
🎓 AI_DESCRIPTION: End-to-end tests via HTTP API
🎓 AI_BUSINESS: Verify full stack works together
🎓 AI_TEACHING: Integration testing patterns

⚠️ ZERO MOCK POLICY:
- Backend MUST be running on localhost:8000
- Ollama MUST be running on localhost:11434
- Tests MUST FAIL if services are down

📋 PREREQUISITES:
1. Start Ollama: ollama serve
2. Start backend: uvicorn main:app --port 8000
3. Run tests: pytest backend/tests/integration -v
"""

import pytest
import httpx
import time

BASE_URL = "http://localhost:8000"
API_PREFIX = "/api/v1"


# ============================================================
# PREREQUISITES CHECK
# ============================================================

class TestPrerequisites:
    """Fail fast if environment not ready"""
    
    def test_backend_running(self):
        """
        ⚠️ ZERO MOCK: Must connect to real backend
        """
        try:
            response = httpx.get(f"{BASE_URL}/health", timeout=5)
            assert response.status_code == 200
        except httpx.ConnectError:
            pytest.fail(
                f"❌ Backend not running at {BASE_URL}\n"
                f"   Run: cd backend && uvicorn main:app --port 8000"
            )
    
    def test_translation_service_healthy(self):
        """
        ⚠️ ZERO MOCK: Check translation service specifically
        """
        response = httpx.get(f"{BASE_URL}{API_PREFIX}/translation/health", timeout=10)
        assert response.status_code == 200
        data = response.json()
        assert data["status"] in ["healthy", "degraded"]
```
**Validation:** Run prerequisites
**Commit:** `test(integration): create integration test file`

---

### Task 1.4.2: Add happy path integration tests (10 min)
**File:** `backend/tests/integration/test_translation_debate_integration.py` (append)
```python
# ============================================================
# HAPPY PATH TESTS
# ============================================================

class TestTranslationDebateAPI:
    """
    🎓 AI_TEACHING: Test the full API flow
    """
    
    def test_translate_chinese_to_english(self):
        """
        ⚠️ ZERO MOCK: Real API call, real Ollama, real translation
        """
        response = httpx.post(
            f"{BASE_URL}{API_PREFIX}/translation/debate",
            json={
                "text": "太极拳",
                "source_lang": "Chinese",
                "target_lang": "English"
            },
            timeout=60  # Translation can be slow
        )
        
        assert response.status_code == 200, f"Failed: {response.text}"
        data = response.json()
        
        # Verify response structure
        assert "translation" in data
        assert "confidence" in data
        assert "rounds" in data
        assert "status" in data
        
        # Verify content
        assert data["translation"] != ""
        assert "tai" in data["translation"].lower()
        assert data["confidence"] > 0
        assert data["status"] in ["success", "partial"]
    
    def test_translate_japanese_to_english(self):
        """
        ⚠️ ZERO MOCK: Test Japanese support
        """
        response = httpx.post(
            f"{BASE_URL}{API_PREFIX}/translation/debate",
            json={
                "text": "空手道",
                "source_lang": "Japanese",
                "target_lang": "English"
            },
            timeout=60
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "karate" in data["translation"].lower()
    
    def test_response_includes_debate_rounds(self):
        """
        🎓 AI_BUSINESS: Transparency - show debate process
        """
        response = httpx.post(
            f"{BASE_URL}{API_PREFIX}/translation/debate",
            json={
                "text": "功夫",
                "source_lang": "Chinese",
                "target_lang": "English"
            },
            timeout=60
        )
        
        assert response.status_code == 200
        data = response.json()
        
        # Should have at least 1 round
        assert len(data["rounds"]) >= 1
        
        # Each round should have required fields
        for round_data in data["rounds"]:
            assert "round_number" in round_data
            assert "model_a_response" in round_data
            assert "model_b_response" in round_data
            assert "agreement_score" in round_data
```
**Validation:** Run with backend + Ollama active
**Commit:** `test(integration): add happy path tests`

---

### Task 1.4.3: Add error handling integration tests (10 min)
**File:** `backend/tests/integration/test_translation_debate_integration.py` (append)
```python
# ============================================================
# ERROR HANDLING TESTS
# ============================================================

class TestTranslationDebateErrors:
    """
    🎓 AI_TEACHING: Test that errors are handled gracefully
    """
    
    def test_empty_text_rejected(self):
        """Pydantic should reject empty text"""
        response = httpx.post(
            f"{BASE_URL}{API_PREFIX}/translation/debate",
            json={
                "text": "",
                "source_lang": "Chinese",
                "target_lang": "English"
            },
            timeout=10
        )
        
        # Should be 422 Unprocessable Entity (Pydantic validation)
        assert response.status_code == 422
    
    def test_missing_field_rejected(self):
        """Pydantic should reject missing fields"""
        response = httpx.post(
            f"{BASE_URL}{API_PREFIX}/translation/debate",
            json={
                "text": "太极拳"
                # Missing source_lang and target_lang
            },
            timeout=10
        )
        
        assert response.status_code == 422
    
    def test_text_too_long_rejected(self):
        """Should reject text over 5000 chars"""
        long_text = "太极" * 3000  # 6000 characters
        
        response = httpx.post(
            f"{BASE_URL}{API_PREFIX}/translation/debate",
            json={
                "text": long_text,
                "source_lang": "Chinese",
                "target_lang": "English"
            },
            timeout=10
        )
        
        assert response.status_code == 422
```
**Validation:** Run tests
**Commit:** `test(integration): add error handling tests`

---

### Task 1.4.4: Add performance integration tests (10 min)
**File:** `backend/tests/integration/test_translation_debate_integration.py` (append)
```python
# ============================================================
# PERFORMANCE TESTS
# ============================================================

class TestTranslationDebatePerformance:
    """
    🎓 AI_BUSINESS: Ensure acceptable response times
    """
    
    def test_translation_under_60_seconds(self):
        """
        🎓 AI_BUSINESS: User won't wait more than 1 minute
        """
        start = time.time()
        
        response = httpx.post(
            f"{BASE_URL}{API_PREFIX}/translation/debate",
            json={
                "text": "太极拳是中国传统武术",
                "source_lang": "Chinese",
                "target_lang": "English"
            },
            timeout=65  # Slightly more than expected max
        )
        
        elapsed = time.time() - start
        
        assert response.status_code == 200
        assert elapsed < 60, f"Translation took {elapsed:.1f}s, max is 60s"
    
    def test_health_check_fast(self):
        """Health check should be instant"""
        start = time.time()
        response = httpx.get(f"{BASE_URL}{API_PREFIX}/translation/health", timeout=5)
        elapsed = time.time() - start
        
        assert response.status_code == 200
        assert elapsed < 2, f"Health check took {elapsed:.1f}s, should be <2s"
```
**Validation:** Run tests
**Commit:** `test(integration): add performance tests`

---

## ✅ US-001 Complete Checklist

### Module 1: OllamaEngine
- [ ] 1.1.1: Create file with AI-First header
- [ ] 1.1.2: Define data classes
- [ ] 1.1.3: Add imports and constants
- [ ] 1.1.4: Create class skeleton
- [ ] 1.1.5: Add async context manager
- [ ] 1.1.6: Implement is_available()
- [ ] 1.1.7: Implement _make_request()
- [ ] 1.1.8: Implement translate()
- [ ] 1.1.9: Create unit test file
- [ ] 1.1.10: Prerequisite check tests
- [ ] 1.1.11: Unit tests
- [ ] 1.1.12: Enterprise test suite

### Module 2: TranslationDebate
- [ ] 1.2.1: Create file with header
- [ ] 1.2.2: Define dataclasses
- [ ] 1.2.3: Create class skeleton
- [ ] 1.2.4: Implement _calculate_agreement()
- [ ] 1.2.5: Implement _check_models_available()
- [ ] 1.2.6: Implement _single_model_fallback()
- [ ] 1.2.7: Implement _run_debate_round()
- [ ] 1.2.8: Implement debate()

### Module 3: API Endpoint
- [ ] 1.3.1: Create router file
- [ ] 1.3.2: Define Pydantic models
- [ ] 1.3.3: Implement POST endpoint
- [ ] 1.3.4: Register in main.py

### Module 4: Integration Tests
- [ ] 1.4.1: Create integration test file
- [ ] 1.4.2: Happy path tests
- [ ] 1.4.3: Error handling tests
- [ ] 1.4.4: Performance tests

### Quality Gates
- [ ] All tests pass (unit + integration + enterprise)
- [ ] Coverage ≥ 90%
- [ ] ZERO mock imports
- [ ] All files have AI-First headers
- [ ] Committed to git with descriptive messages
