"""
# AI_MODULE: AudioAPI
# AI_VERSION: 1.0.0
# AI_DESCRIPTION: API router per sistema audio - TTS, voice cloning, styling, pronuncia
# AI_BUSINESS: Espone via REST il sistema audio per generazione TTS multilingua,
#              voice cloning XTTS, audio styling, e database pronuncie arti marziali.
# AI_TEACHING: Router FastAPI che usa AudioManager come facade. Pattern dependency injection
#              per auth e DB. Supporta upload file per voice cloning.
# AI_DEPENDENCIES: FastAPI, AudioManager, pydantic
# AI_COPYRIGHT: 2025 Media Center Arti Marziali - All Rights Reserved
# AI_CREATED: 2025-12-13

Audio API Router
================

Endpoints per sistema audio:
- TTS generation con multi-engine (Edge, Coqui, pyttsx3)
- Voice cloning con XTTS v2
- Audio styling con preset (dojo_reverb, clear_voice, etc.)
- Database pronuncie termini arti marziali
"""

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form, status
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from enum import Enum
import logging
import os
import tempfile
import shutil

from core.security import get_current_user, get_current_admin_user
from models.user import User

logger = logging.getLogger(__name__)

router = APIRouter()  # Prefix gestito da main.py: /api/v1/audio


# ==================== Pydantic Schemas ====================

class TTSEngineType(str, Enum):
    EDGE = "edge"
    COQUI = "coqui"
    PYTTSX3 = "pyttsx3"
    AUTO = "auto"


class StylePresetType(str, Enum):
    DOJO_REVERB = "dojo_reverb"
    CLEAR_VOICE = "clear_voice"
    WARM_NARRATOR = "warm_narrator"
    DRAMATIC = "dramatic"
    MEDITATION = "meditation"
    TRAINING = "training"
    ANNOUNCEMENT = "announcement"
    WHISPER = "whisper"
    BRIGHT = "bright"
    DEEP = "deep"
    TELEPHONE = "telephone"


class LanguageCodeType(str, Enum):
    JA = "ja"
    ZH = "zh"
    KO = "ko"
    VI = "vi"
    TH = "th"
    ID = "id"
    IT = "it"
    EN = "en"
    ES = "es"


class MartialArtStyleType(str, Enum):
    KARATE = "karate"
    JUDO = "judo"
    AIKIDO = "aikido"
    KENDO = "kendo"
    TAEKWONDO = "taekwondo"
    KUNG_FU = "kung_fu"
    TAI_CHI = "tai_chi"
    MUAY_THAI = "muay_thai"
    CAPOEIRA = "capoeira"
    GENERIC = "generic"


class TermCategoryType(str, Enum):
    TECHNIQUE = "technique"
    STANCE = "stance"
    MOVEMENT = "movement"
    COMMAND = "command"
    GREETING = "greeting"
    NUMBER = "number"
    BODY_PART = "body_part"
    WEAPON = "weapon"
    RANK = "rank"
    PHILOSOPHY = "philosophy"


class TTSRequest(BaseModel):
    """Request per generazione TTS."""
    text: str = Field(..., min_length=1, max_length=5000, description="Testo da sintetizzare")
    language: str = Field(default="it", description="Codice lingua ISO")
    voice_id: Optional[str] = Field(default=None, description="ID voce specifica")
    engine: TTSEngineType = Field(default=TTSEngineType.AUTO, description="Engine TTS")
    rate: float = Field(default=1.0, ge=0.5, le=2.0, description="Velocita parlato")
    pitch: float = Field(default=1.0, ge=0.5, le=2.0, description="Altezza voce")
    volume: float = Field(default=1.0, ge=0.0, le=1.0, description="Volume")
    store: bool = Field(default=True, description="Salva in storage")


class TTSResponse(BaseModel):
    """Response generazione TTS."""
    success: bool
    audio_id: Optional[str] = None
    audio_path: Optional[str] = None
    duration_seconds: Optional[float] = None
    engine_used: Optional[str] = None
    voice_used: Optional[str] = None
    cached: bool = False
    error: Optional[str] = None


class VoiceProfileRequest(BaseModel):
    """Request per creazione profilo voce."""
    name: str = Field(..., min_length=1, max_length=100)
    language: str = Field(default="it")
    description: Optional[str] = None


class VoiceProfileResponse(BaseModel):
    """Response profilo voce."""
    id: str
    name: str
    language: str
    description: Optional[str] = None
    reference_path: str
    is_active: bool = True
    created_at: str
    created_by: Optional[str] = None


class CloneVoiceRequest(BaseModel):
    """Request per voice cloning."""
    text: str = Field(..., min_length=1, max_length=5000)
    profile_id: str = Field(..., description="ID profilo voce")
    target_language: Optional[str] = None
    speed: float = Field(default=1.0, ge=0.5, le=2.0)
    store: bool = Field(default=True)


class StyleAudioRequest(BaseModel):
    """Request per audio styling."""
    audio_id: str = Field(..., description="ID audio da stylare")
    style: StylePresetType = Field(..., description="Preset stile")
    store: bool = Field(default=True)


class StyleAudioResponse(BaseModel):
    """Response audio styling."""
    success: bool
    audio_id: Optional[str] = None
    audio_path: Optional[str] = None
    duration_seconds: Optional[float] = None
    style_applied: Optional[str] = None
    processing_time_ms: Optional[float] = None
    error: Optional[str] = None


class PronunciationRequest(BaseModel):
    """Request per aggiungere pronuncia."""
    term: str = Field(..., min_length=1, max_length=100)
    language: LanguageCodeType
    romanization: str = Field(..., min_length=1, max_length=200)
    category: TermCategoryType
    martial_art: MartialArtStyleType
    phonetic: Optional[str] = None
    meaning: Optional[str] = None
    notes: Optional[str] = None


class PronunciationResponse(BaseModel):
    """Response pronuncia."""
    id: str
    term: str
    language: str
    romanization: str
    phonetic: Optional[str] = None
    category: str
    martial_art: str
    meaning: Optional[str] = None
    notes: Optional[str] = None
    audio_url: Optional[str] = None
    is_verified: bool = False
    vote_count: int = 0


class AudioStorageStats(BaseModel):
    """Statistiche storage audio."""
    total_files: int
    total_size_mb: float
    files_by_category: Dict[str, int]
    size_by_category: Dict[str, int]
    dedup_savings_bytes: int


class SystemInfoResponse(BaseModel):
    """Info sistema audio."""
    availability: Dict[str, bool]
    storage: AudioStorageStats
    pronunciation: Dict[str, Any]
    voice_profiles_count: int
    supported_languages: List[str]


# ==================== Helper Functions ====================

async def get_audio_manager():
    """Dependency per ottenere AudioManager."""
    from services.audio_system import AudioManager
    return await AudioManager.get_instance()


# ==================== TTS Endpoints ====================

@router.post("/tts", response_model=TTSResponse, summary="Genera audio TTS")
async def generate_tts(
    request: TTSRequest,
    current_user: User = Depends(get_current_user),
    manager = Depends(get_audio_manager),
):
    """
    Genera audio Text-to-Speech.

    Supporta multiple engine:
    - **edge**: Microsoft Edge TTS (online, alta qualita)
    - **coqui**: Coqui TTS (offline, customizzabile)
    - **pyttsx3**: pyttsx3 (offline, basic)
    - **auto**: Seleziona automaticamente la migliore disponibile
    """
    try:
        from services.audio_system import TTSEngine

        engine_map = {
            TTSEngineType.EDGE: TTSEngine.EDGE,
            TTSEngineType.COQUI: TTSEngine.COQUI,
            TTSEngineType.PYTTSX3: TTSEngine.PYTTSX3,
            TTSEngineType.AUTO: TTSEngine.AUTO,
        }

        result = await manager.generate_tts(
            text=request.text,
            language=request.language,
            voice_id=request.voice_id,
            engine=engine_map[request.engine],
            rate=request.rate,
            pitch=request.pitch,
            volume=request.volume,
            store=request.store,
        )

        return TTSResponse(
            success=result.success,
            audio_id=result.audio_id,
            audio_path=result.audio_path,
            duration_seconds=result.duration_seconds,
            engine_used=result.metadata.get("engine"),
            voice_used=result.metadata.get("voice"),
            cached=result.metadata.get("cached", False),
            error=result.error,
        )
    except Exception as e:
        logger.error(f"TTS generation error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/tts/voices", summary="Lista voci TTS disponibili")
async def get_tts_voices(
    language: Optional[str] = None,
    engine: Optional[TTSEngineType] = None,
    current_user: User = Depends(get_current_user),
    manager = Depends(get_audio_manager),
):
    """Lista tutte le voci TTS disponibili, filtrate per lingua o engine."""
    try:
        from services.audio_system import TTSEngine

        engine_param = None
        if engine:
            engine_map = {
                TTSEngineType.EDGE: TTSEngine.EDGE,
                TTSEngineType.COQUI: TTSEngine.COQUI,
                TTSEngineType.PYTTSX3: TTSEngine.PYTTSX3,
            }
            engine_param = engine_map.get(engine)

        voices = await manager.get_tts_voices(language, engine_param)
        return {
            "voices": [
                {
                    "id": v.id,
                    "name": v.name,
                    "language": v.language,
                    "gender": v.gender,
                    "engine": v.engine,
                }
                for v in voices
            ],
            "count": len(voices),
        }
    except Exception as e:
        logger.error(f"Error getting voices: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/tts/engines", summary="Lista engine TTS disponibili")
async def get_available_engines(
    current_user: User = Depends(get_current_user),
    manager = Depends(get_audio_manager),
):
    """Restituisce gli engine TTS attualmente disponibili nel sistema."""
    try:
        engines = await manager.get_available_tts_engines()
        return {
            "engines": [e.value for e in engines],
            "count": len(engines),
        }
    except Exception as e:
        logger.error(f"Error getting engines: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ==================== Voice Cloning Endpoints ====================

@router.post("/voice-profiles", response_model=VoiceProfileResponse, summary="Crea profilo voce")
async def create_voice_profile(
    name: str = Form(...),
    language: str = Form(default="it"),
    description: Optional[str] = Form(default=None),
    reference_audio: UploadFile = File(..., description="Audio di riferimento (WAV, 10-30 secondi)"),
    current_user: User = Depends(get_current_user),
    manager = Depends(get_audio_manager),
):
    """
    Crea un nuovo profilo voce per cloning.

    L'audio di riferimento deve essere:
    - Formato: WAV
    - Durata: 10-30 secondi
    - Qualita: Parlato chiaro, senza rumore di fondo
    """
    # Salva file temporaneo
    temp_dir = tempfile.mkdtemp()
    temp_path = os.path.join(temp_dir, reference_audio.filename)

    try:
        with open(temp_path, "wb") as f:
            shutil.copyfileobj(reference_audio.file, f)

        # Valida reference
        validation = await manager.validate_voice_reference(temp_path)
        if not validation.is_valid:
            raise HTTPException(
                status_code=400,
                detail=f"Audio reference non valido: {', '.join(validation.issues)}"
            )

        # Crea profilo
        profile = await manager.create_voice_profile(
            name=name,
            reference_path=temp_path,
            language=language,
            description=description,
            created_by=str(current_user.id),
        )

        return VoiceProfileResponse(
            id=profile.id,
            name=profile.name,
            language=profile.language,
            description=profile.description,
            reference_path=profile.reference_path,
            is_active=profile.is_active,
            created_at=profile.created_at,
            created_by=profile.created_by,
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating voice profile: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        # Cleanup temp (il profilo copia il file)
        shutil.rmtree(temp_dir, ignore_errors=True)


@router.get("/voice-profiles", summary="Lista profili voce")
async def list_voice_profiles(
    current_user: User = Depends(get_current_user),
    manager = Depends(get_audio_manager),
):
    """Lista tutti i profili voce disponibili."""
    try:
        profiles = await manager.list_voice_profiles()
        return {
            "profiles": [
                {
                    "id": p.id,
                    "name": p.name,
                    "language": p.language,
                    "description": p.description,
                    "is_active": p.is_active,
                    "created_at": p.created_at,
                }
                for p in profiles
            ],
            "count": len(profiles),
        }
    except Exception as e:
        logger.error(f"Error listing profiles: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/voice-profiles/{profile_id}", response_model=VoiceProfileResponse)
async def get_voice_profile(
    profile_id: str,
    current_user: User = Depends(get_current_user),
    manager = Depends(get_audio_manager),
):
    """Ottiene dettagli profilo voce."""
    profile = await manager.get_voice_profile(profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Profilo voce non trovato")

    return VoiceProfileResponse(
        id=profile.id,
        name=profile.name,
        language=profile.language,
        description=profile.description,
        reference_path=profile.reference_path,
        is_active=profile.is_active,
        created_at=profile.created_at,
        created_by=profile.created_by,
    )


@router.delete("/voice-profiles/{profile_id}", summary="Elimina profilo voce")
async def delete_voice_profile(
    profile_id: str,
    current_user: User = Depends(get_current_admin_user),
    manager = Depends(get_audio_manager),
):
    """Elimina un profilo voce (solo admin)."""
    deleted = await manager.delete_voice_profile(profile_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Profilo voce non trovato")

    return {"message": "Profilo voce eliminato", "profile_id": profile_id}


@router.post("/clone", response_model=TTSResponse, summary="Genera audio con voce clonata")
async def clone_voice(
    request: CloneVoiceRequest,
    current_user: User = Depends(get_current_user),
    manager = Depends(get_audio_manager),
):
    """
    Genera audio usando una voce clonata.

    Richiede un profilo voce creato precedentemente con /voice-profiles.
    """
    try:
        result = await manager.clone_voice(
            text=request.text,
            profile_id=request.profile_id,
            target_language=request.target_language,
            speed=request.speed,
            store=request.store,
        )

        return TTSResponse(
            success=result.success,
            audio_id=result.audio_id,
            audio_path=result.audio_path,
            duration_seconds=result.duration_seconds,
            error=result.error,
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Voice cloning error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/clone/validate", summary="Valida audio per voice cloning")
async def validate_voice_reference(
    audio: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
    manager = Depends(get_audio_manager),
):
    """Valida un file audio per uso come reference in voice cloning."""
    temp_dir = tempfile.mkdtemp()
    temp_path = os.path.join(temp_dir, audio.filename)

    try:
        with open(temp_path, "wb") as f:
            shutil.copyfileobj(audio.file, f)

        validation = await manager.validate_voice_reference(temp_path)

        return {
            "is_valid": validation.is_valid,
            "duration_seconds": validation.duration_seconds,
            "sample_rate": validation.sample_rate,
            "channels": validation.channels,
            "issues": validation.issues,
            "recommendations": validation.recommendations,
        }
    except Exception as e:
        logger.error(f"Validation error: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


# ==================== Styling Endpoints ====================

@router.post("/style", response_model=StyleAudioResponse, summary="Applica stile audio")
async def apply_style(
    request: StyleAudioRequest,
    current_user: User = Depends(get_current_user),
    manager = Depends(get_audio_manager),
):
    """
    Applica uno stile predefinito a un audio esistente.

    Stili disponibili:
    - **dojo_reverb**: Riverbero tipo dojo
    - **clear_voice**: Voce chiara per tutorial
    - **warm_narrator**: Voce calda narratore
    - **dramatic**: Effetto drammatico
    - **meditation**: Calmo per meditazione
    """
    try:
        # Ottieni path audio
        audio_path = await manager.get_audio(request.audio_id)
        if not audio_path:
            raise HTTPException(status_code=404, detail="Audio non trovato")

        result = await manager.apply_style(
            audio_path=str(audio_path),
            style=request.style.value,
            store=request.store,
        )

        return StyleAudioResponse(
            success=result.success,
            audio_id=result.audio_id,
            audio_path=result.audio_path,
            duration_seconds=result.duration_seconds,
            style_applied=result.metadata.get("style"),
            processing_time_ms=result.metadata.get("processing_time_ms"),
            error=result.error,
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Styling error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/style/presets", summary="Lista preset stile disponibili")
async def get_style_presets(
    current_user: User = Depends(get_current_user),
    manager = Depends(get_audio_manager),
):
    """Lista tutti i preset di stile audio disponibili."""
    try:
        presets = await manager.get_style_presets()
        return {
            "presets": [
                {
                    "name": p.name,
                    "description": p.description,
                    "parameters": p.parameters,
                }
                for p in presets
            ],
            "count": len(presets),
        }
    except Exception as e:
        logger.error(f"Error getting presets: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/analyze", summary="Analizza caratteristiche audio")
async def analyze_audio(
    audio_id: str,
    current_user: User = Depends(get_current_user),
    manager = Depends(get_audio_manager),
):
    """Analizza le caratteristiche di un file audio."""
    try:
        audio_path = await manager.get_audio(audio_id)
        if not audio_path:
            raise HTTPException(status_code=404, detail="Audio non trovato")

        analysis = await manager.analyze_audio(str(audio_path))
        suggested = await manager.suggest_style(str(audio_path))

        return {
            **analysis,
            "suggested_style": suggested.value if suggested else None,
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Analysis error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ==================== Pronunciation Endpoints ====================

@router.get("/pronunciation/{term}", summary="Cerca pronuncia termine")
async def get_pronunciation(
    term: str,
    language: Optional[LanguageCodeType] = None,
    current_user: User = Depends(get_current_user),
    manager = Depends(get_audio_manager),
):
    """
    Cerca la pronuncia di un termine di arti marziali.

    Ricerca per termine originale, romanizzazione, o full-text.
    """
    try:
        from services.audio_system import LanguageCode

        lang_param = None
        if language:
            lang_param = LanguageCode(language.value)

        entries = await manager.get_pronunciation(term, lang_param)

        return {
            "term": term,
            "results": [
                {
                    "id": e.id,
                    "term": e.term,
                    "language": e.language,
                    "romanization": e.romanization,
                    "phonetic": e.phonetic,
                    "category": e.category,
                    "martial_art": e.martial_art,
                    "meaning": e.meaning,
                    "notes": e.notes,
                    "is_verified": e.is_verified,
                    "vote_count": e.vote_count,
                }
                for e in entries
            ],
            "count": len(entries),
        }
    except Exception as e:
        logger.error(f"Pronunciation search error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/pronunciation", response_model=PronunciationResponse, summary="Aggiungi pronuncia")
async def add_pronunciation(
    request: PronunciationRequest,
    current_user: User = Depends(get_current_user),
    manager = Depends(get_audio_manager),
):
    """Aggiunge una nuova pronuncia al database."""
    try:
        from services.audio_system import LanguageCode, TermCategory, MartialArtStyle
        from services.audio_system.pronunciation_db import TermCategory as TC, MartialArtStyle as MA

        entry = await manager.add_pronunciation(
            term=request.term,
            language=LanguageCode(request.language.value),
            romanization=request.romanization,
            category=TC(request.category.value),
            martial_art=MA(request.martial_art.value),
            phonetic=request.phonetic,
            meaning=request.meaning,
            notes=request.notes,
        )

        return PronunciationResponse(
            id=entry.id,
            term=entry.term,
            language=entry.language,
            romanization=entry.romanization,
            phonetic=entry.phonetic,
            category=entry.category,
            martial_art=entry.martial_art,
            meaning=entry.meaning,
            notes=entry.notes,
            is_verified=entry.is_verified,
            vote_count=entry.vote_count,
        )
    except Exception as e:
        logger.error(f"Add pronunciation error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/pronunciation/{entry_id}/audio", summary="Genera audio pronuncia")
async def generate_pronunciation_audio(
    entry_id: str,
    voice_profile_id: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    manager = Depends(get_audio_manager),
):
    """Genera audio per una entry di pronuncia."""
    try:
        result = await manager.generate_pronunciation_audio(
            entry_id=entry_id,
            voice_profile_id=voice_profile_id,
        )

        if not result.success:
            raise HTTPException(status_code=400, detail=result.error)

        return {
            "success": True,
            "audio_id": result.audio_id,
            "audio_path": result.audio_path,
            "duration_seconds": result.duration_seconds,
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Generate pronunciation audio error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/pronunciation/seed", summary="Popola DB con termini base")
async def seed_pronunciation_db(
    current_user: User = Depends(get_current_admin_user),
    manager = Depends(get_audio_manager),
):
    """Popola il database pronuncie con i termini base (solo admin)."""
    try:
        count = await manager.seed_pronunciation_db()
        return {
            "message": "Database pronuncie popolato",
            "terms_added": count,
        }
    except Exception as e:
        logger.error(f"Seed error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ==================== Storage Endpoints ====================

@router.get("/files/{audio_id}", summary="Download audio")
async def get_audio_file(
    audio_id: str,
    current_user: User = Depends(get_current_user),
    manager = Depends(get_audio_manager),
):
    """Scarica un file audio per ID."""
    try:
        audio_path = await manager.get_audio(audio_id)
        if not audio_path or not audio_path.exists():
            raise HTTPException(status_code=404, detail="Audio non trovato")

        return FileResponse(
            path=str(audio_path),
            media_type="audio/wav",
            filename=audio_path.name,
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Download error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/files/{audio_id}/metadata", summary="Metadata audio")
async def get_audio_metadata(
    audio_id: str,
    current_user: User = Depends(get_current_user),
    manager = Depends(get_audio_manager),
):
    """Ottiene i metadata di un file audio."""
    try:
        metadata = await manager.get_audio_metadata(audio_id)
        if not metadata:
            raise HTTPException(status_code=404, detail="Audio non trovato")

        return {
            "id": metadata.id,
            "filename": metadata.filename,
            "format": metadata.format,
            "category": metadata.category,
            "size_bytes": metadata.size_bytes,
            "duration_seconds": metadata.duration_seconds,
            "sample_rate": metadata.sample_rate,
            "channels": metadata.channels,
            "created_at": metadata.created_at,
            "file_hash": metadata.file_hash,
            "extra": metadata.extra,
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Metadata error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/files/{audio_id}", summary="Elimina audio")
async def delete_audio(
    audio_id: str,
    secure: bool = False,
    current_user: User = Depends(get_current_admin_user),
    manager = Depends(get_audio_manager),
):
    """Elimina un file audio (solo admin)."""
    try:
        deleted = await manager.delete_audio(audio_id, secure)
        if not deleted:
            raise HTTPException(status_code=404, detail="Audio non trovato")

        return {
            "message": "Audio eliminato",
            "audio_id": audio_id,
            "secure_delete": secure,
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Delete error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/storage/stats", response_model=AudioStorageStats, summary="Statistiche storage")
async def get_storage_stats(
    current_user: User = Depends(get_current_admin_user),
    manager = Depends(get_audio_manager),
):
    """Ottiene statistiche dello storage audio (solo admin)."""
    try:
        stats = await manager.get_storage_stats()
        return AudioStorageStats(
            total_files=stats["total_files"],
            total_size_mb=stats["total_size_mb"],
            files_by_category=stats["files_by_category"],
            size_by_category=stats["size_by_category"],
            dedup_savings_bytes=stats["dedup_savings_bytes"],
        )
    except Exception as e:
        logger.error(f"Stats error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/storage/cleanup", summary="Cleanup file temporanei")
async def cleanup_temp_files(
    max_age_hours: Optional[int] = None,
    current_user: User = Depends(get_current_admin_user),
    manager = Depends(get_audio_manager),
):
    """Pulisce i file temporanei (solo admin)."""
    try:
        cleaned = await manager.cleanup_temp_files(max_age_hours)
        return {
            "message": "Cleanup completato",
            "files_removed": cleaned,
        }
    except Exception as e:
        logger.error(f"Cleanup error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ==================== System Info ====================

@router.get("/system/info", response_model=SystemInfoResponse, summary="Info sistema audio")
async def get_system_info(
    current_user: User = Depends(get_current_admin_user),
    manager = Depends(get_audio_manager),
):
    """Ottiene informazioni complete sul sistema audio (solo admin)."""
    try:
        info = await manager.get_system_info()

        storage = info["storage"]
        return SystemInfoResponse(
            availability=info["availability"],
            storage=AudioStorageStats(
                total_files=storage["total_files"],
                total_size_mb=storage["total_size_mb"],
                files_by_category=storage["files_by_category"],
                size_by_category=storage["size_by_category"],
                dedup_savings_bytes=storage["dedup_savings_bytes"],
            ),
            pronunciation=info["pronunciation"],
            voice_profiles_count=info["voice_profiles_count"],
            supported_languages=info["supported_languages"],
        )
    except Exception as e:
        logger.error(f"System info error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/system/health", summary="Health check sistema audio")
async def health_check(
    manager = Depends(get_audio_manager),
):
    """Health check per il sistema audio."""
    try:
        availability = await manager.is_fully_available()

        any_tts = any([
            availability.get("tts_edge"),
            availability.get("tts_coqui"),
            availability.get("tts_pyttsx3"),
        ])

        return {
            "status": "healthy" if any_tts else "degraded",
            "storage_ok": availability.get("storage", False),
            "pronunciation_db_ok": availability.get("pronunciation_db", False),
            "tts_available": any_tts,
            "voice_cloner_ok": availability.get("voice_cloner", False),
            "voice_styler_ok": availability.get("voice_styler", False),
        }
    except Exception as e:
        logger.error(f"Health check error: {e}")
        return {
            "status": "unhealthy",
            "error": str(e),
        }
