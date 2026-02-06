"""
================================================================================
    MEDIA CENTER ARTI MARZIALI - Translation Debate API
================================================================================

    AI_MODULE: Translation Debate API Endpoints
    AI_DESCRIPTION: REST API per traduzione multi-LLM con debate
    AI_BUSINESS: Interfaccia per traduzioni alta qualita
    AI_TEACHING: FastAPI, async endpoints, Pydantic validation

    ENDPOINTS:
    - POST /translate/debate - Traduzione con debate
    - POST /translate/simple - Traduzione semplice
    - POST /translate/critique - Critica traduzione esistente
    - GET /translate/config - Status configurazione LLM

================================================================================
"""

from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field
from typing import Any, Dict, List, Optional
import logging

from services.translation import (
    get_debate_service,
    DebateConfig,
    DebateStrategy,
    get_llm_config,
    get_glossary_context
)

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Translation Debate"])


# ==============================================================================
# REQUEST/RESPONSE MODELS
# ==============================================================================
class TranslateRequest(BaseModel):
    """
    AI_MODULE: Translation Request
    AI_DESCRIPTION: Richiesta traduzione

    CAMPI:
    - text: Testo da tradurre (obbligatorio)
    - source_lang: Lingua sorgente (ja, zh, ko, en, etc.)
    - target_lang: Lingua target (it, en, es, etc.)
    - use_glossary: Usa glossario arti marziali
    - martial_art_style: Stile specifico (karate, kungfu, taekwondo)
    """
    text: str = Field(..., min_length=1, max_length=10000)
    source_lang: str = Field(default="ja", pattern="^[a-z]{2}$")
    target_lang: str = Field(default="it", pattern="^[a-z]{2}$")
    use_glossary: bool = True
    martial_art_style: Optional[str] = None

    class Config:
        json_schema_extra = {
            "example": {
                "text": "mae geri",
                "source_lang": "ja",
                "target_lang": "it",
                "use_glossary": True,
                "martial_art_style": "karate"
            }
        }


class DebateTranslateRequest(TranslateRequest):
    """Richiesta traduzione con debate"""
    max_rounds: int = Field(default=5, ge=1, le=10)
    confidence_threshold: float = Field(default=0.85, ge=0.5, le=1.0)
    strategy: str = Field(default="iterative")


class CritiqueRequest(BaseModel):
    """Richiesta critica traduzione"""
    original_text: str = Field(..., min_length=1)
    translation: str = Field(..., min_length=1)
    source_lang: str = Field(default="ja")
    target_lang: str = Field(default="it")


class TranslationResponse(BaseModel):
    """Risposta traduzione semplice"""
    translation: str
    confidence: float
    alternatives: List[str] = []
    cultural_note: Optional[str] = None
    translator_note: Optional[str] = None
    provider: str
    processing_time_ms: float


class DebateResponse(BaseModel):
    """Risposta traduzione con debate"""
    translation: str
    confidence: float
    consensus_reached: bool
    num_rounds: int
    total_time_ms: float
    debate_history: List[Dict[str, Any]] = []
    alternatives: List[str] = []


class CritiqueResponse(BaseModel):
    """Risposta critica"""
    is_acceptable: bool
    issues: List[str] = []
    suggestions: List[str] = []
    confidence_adjustment: float
    reasoning: str


class ConfigResponse(BaseModel):
    """Risposta configurazione"""
    providers: Dict[str, Any]
    routing_enabled: bool
    enabled_providers: List[str]


# ==============================================================================
# ENDPOINTS
# ==============================================================================
@router.post("/translate/debate", response_model=DebateResponse)
async def translate_with_debate(request: DebateTranslateRequest):
    """
    Traduce testo usando sistema debate multi-LLM.

    PROCESSO:
    1. LLM Translator produce traduzione
    2. LLM Critic valuta traduzione
    3. Se problemi: Translator risponde
    4. Ripete fino a consenso o max rounds

    BUSINESS: Qualita traduzione +15% vs single LLM

    NOTA: Piu lento (10-60 secondi) ma piu accurato
    """
    try:
        # Ottieni service
        service = get_debate_service()

        # Configura per questa richiesta
        config = DebateConfig(
            max_rounds=request.max_rounds,
            confidence_threshold=request.confidence_threshold,
            strategy=DebateStrategy(request.strategy)
        )

        # Prepara context
        context = {}
        if request.use_glossary:
            context.update(get_glossary_context(request.source_lang))
        if request.martial_art_style:
            context["style"] = request.martial_art_style

        # Inizializza se necessario
        if not service.is_initialized:
            await service.initialize()

        # Esegui debate
        result = await service.translate_with_debate(
            text=request.text,
            source_lang=request.source_lang,
            target_lang=request.target_lang,
            context=context if context else None
        )

        return DebateResponse(
            translation=result.translation.text,
            confidence=result.translation.confidence,
            consensus_reached=result.consensus_reached,
            num_rounds=len(result.rounds),
            total_time_ms=result.total_time_ms,
            debate_history=[
                {
                    "round": r.round_number,
                    "translation": r.translation.text,
                    "critique": r.critique.to_dict() if r.critique else None,
                    "consensus": r.consensus_reached
                }
                for r in result.rounds
            ],
            alternatives=result.translation.alternatives
        )

    except Exception as e:
        logger.error(f"Errore debate translation: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Errore traduzione: {str(e)}"
        )


@router.post("/translate/simple", response_model=TranslationResponse)
async def translate_simple(request: TranslateRequest):
    """
    Traduzione semplice senza debate.

    Utile per:
    - Preview veloci
    - Testi brevi
    - Quando velocita > qualita
    """
    try:
        service = get_debate_service()

        context = {}
        if request.use_glossary:
            context.update(get_glossary_context(request.source_lang))
        if request.martial_art_style:
            context["style"] = request.martial_art_style

        if not service.is_initialized:
            await service.initialize()

        result = await service.translate_simple(
            text=request.text,
            source_lang=request.source_lang,
            target_lang=request.target_lang,
            context=context if context else None
        )

        return TranslationResponse(
            translation=result.text,
            confidence=result.confidence,
            alternatives=result.alternatives,
            cultural_note=result.cultural_note,
            translator_note=result.translator_note,
            provider=result.provider,
            processing_time_ms=result.processing_time_ms
        )

    except Exception as e:
        logger.error(f"Errore simple translation: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Errore traduzione: {str(e)}"
        )


@router.post("/translate/critique", response_model=CritiqueResponse)
async def critique_translation(request: CritiqueRequest):
    """
    Critica una traduzione esistente.

    Utile per:
    - Validare traduzioni umane
    - Quality assurance
    - Feedback su traduzioni esterne
    """
    try:
        service = get_debate_service()

        if not service.is_initialized:
            await service.initialize()

        result = await service.critique_translation(
            original_text=request.original_text,
            translation=request.translation,
            source_lang=request.source_lang,
            target_lang=request.target_lang
        )

        return CritiqueResponse(
            is_acceptable=result.is_acceptable,
            issues=result.issues,
            suggestions=result.suggestions,
            confidence_adjustment=result.confidence_adjustment,
            reasoning=result.reasoning
        )

    except Exception as e:
        logger.error(f"Errore critique: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Errore critica: {str(e)}"
        )


@router.get("/translate/config", response_model=ConfigResponse)
async def get_translation_config():
    """
    Ottiene configurazione corrente LLM.

    Ritorna:
    - Provider disponibili
    - Quali sono abilitati
    - Status routing
    """
    try:
        config = get_llm_config()
        status = config.get_status()

        return ConfigResponse(
            providers=status["providers"],
            routing_enabled=status["routing_enabled"],
            enabled_providers=status["enabled_providers"]
        )

    except Exception as e:
        logger.error(f"Errore config: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Errore configurazione: {str(e)}"
        )


@router.get("/translate/glossary/{lang}")
async def get_glossary(lang: str):
    """
    Ottiene glossario arti marziali per lingua.

    Args:
        lang: Codice lingua (ja, zh, ko)

    Returns:
        Dizionario termini
    """
    from services.translation import MARTIAL_ARTS_GLOSSARY

    if lang not in MARTIAL_ARTS_GLOSSARY:
        raise HTTPException(
            status_code=404,
            detail=f"Glossario non disponibile per lingua: {lang}"
        )

    return {
        "language": lang,
        "terms": MARTIAL_ARTS_GLOSSARY[lang],
        "count": len(MARTIAL_ARTS_GLOSSARY[lang])
    }


@router.get("/translate/health")
async def translation_health():
    """
    Health check per servizio traduzione.

    Verifica:
    - Ollama raggiungibile
    - Modelli disponibili
    """
    import httpx

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.get("http://localhost:11434/api/tags")

            if response.status_code == 200:
                models = response.json().get("models", [])
                return {
                    "status": "healthy",
                    "ollama": "connected",
                    "models_available": [m["name"] for m in models],
                    "models_count": len(models)
                }
            else:
                return {
                    "status": "degraded",
                    "ollama": f"error: {response.status_code}",
                    "models_available": []
                }

    except httpx.ConnectError:
        return {
            "status": "unhealthy",
            "ollama": "not_reachable",
            "models_available": [],
            "hint": "Avvia Ollama con: ollama serve"
        }
    except Exception as e:
        return {
            "status": "error",
            "ollama": str(e),
            "models_available": []
        }
