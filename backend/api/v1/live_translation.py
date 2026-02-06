"""
🌐 Live Translation API Router
WebSocket endpoints for real-time subtitle translation
"""

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import List, Optional
import asyncio
import json
import logging

from core.database import get_db
from core.security import get_current_user, get_current_admin_user
from models.user import User
from models.video import LiveEvent
from services.live_translation.translation_manager import (
    translation_manager,
    subtitle_message,
    translation_started,
    translation_stopped,
    language_stats_message
)
from services.live_translation.service_factory import (
    get_speech_service,
    get_translation_service,
    get_provider_info,
    switch_provider
)

logger = logging.getLogger(__name__)

router = APIRouter()  # No prefix here - prefix is set in main.py


# === WEBSOCKET FOR VIEWERS (RECEIVE SUBTITLES) ===

@router.websocket("/events/{event_id}/subtitles")
async def subtitle_websocket(
    event_id: str,
    websocket: WebSocket,
    language: str = "it",  # Default language
):
    """
    WebSocket endpoint for viewers to receive live subtitles

    Clients connect specifying their preferred language.
    They receive real-time subtitles translated to that language.

    Query params:
    - language: ISO language code (it, en, es, fr, de, etc.)
    """
    await translation_manager.connect(event_id, language, websocket)

    try:
        while True:
            # Keep connection alive and handle client messages
            data = await websocket.receive_text()

            try:
                message = json.loads(data)

                # Handle client messages (ping, language change, etc.)
                if message.get("type") == "ping":
                    await websocket.send_json({
                        "type": "pong",
                        "timestamp": message.get("timestamp")
                    })

                elif message.get("type") == "change_language":
                    new_language = message.get("language")
                    if new_language:
                        # Disconnect from old language, connect to new
                        translation_manager.disconnect(event_id, language, websocket)
                        language = new_language
                        await translation_manager.connect(event_id, language, websocket)

            except json.JSONDecodeError:
                logger.warning(f"Invalid JSON from client: {data}")

    except WebSocketDisconnect:
        translation_manager.disconnect(event_id, language, websocket)
        logger.info(f"Viewer disconnected from event {event_id} ({language})")


# === WEBSOCKET FOR BROADCASTER (SEND AUDIO) ===

@router.websocket("/events/{event_id}/broadcast")
async def broadcast_websocket(
    event_id: str,
    websocket: WebSocket,
    source_language: str = "it-IT"
):
    """
    WebSocket endpoint for broadcasters to send audio stream

    This endpoint:
    1. Receives audio chunks from the broadcaster
    2. Sends audio to Speech-to-Text API
    3. Translates recognized text to multiple languages
    4. Broadcasts subtitles to all viewers

    Query params:
    - source_language: Source language code (it-IT, en-US, etc.)
    """
    await websocket.accept()

    # Start translation session
    target_languages = ["en", "es", "fr", "de"]  # Default target languages
    source_lang_code = source_language.split("-")[0]  # "it-IT" -> "it"

    translation_manager.start_session(
        event_id,
        source_language=source_lang_code,
        target_languages=target_languages
    )

    # Notify all viewers that translation has started
    await translation_manager.broadcast_to_all_languages(
        event_id,
        "translation_started",
        {
            "source_language": source_lang_code,
            "available_languages": target_languages
        }
    )

    # Get services
    speech_service = get_speech_service()
    translation_service = get_translation_service()

    try:
        # Buffer for audio chunks
        audio_queue = asyncio.Queue()

        async def audio_generator():
            """Generator that yields audio chunks from the queue"""
            while True:
                chunk = await audio_queue.get()
                if chunk is None:  # Stop signal
                    break
                yield chunk

        # Start speech recognition task
        async def process_transcriptions():
            """Process transcriptions and broadcast subtitles"""
            async for result in speech_service.transcribe_stream(
                audio_generator(),
                language_code=source_language
            ):
                if "error" in result:
                    logger.error(f"Speech-to-Text error: {result['error']}")
                    continue

                text = result.get("text", "")
                is_final = result.get("is_final", False)
                confidence = result.get("confidence")

                if not text:
                    continue

                # Broadcast original language subtitle
                await translation_manager.broadcast_subtitle(
                    event_id,
                    source_lang_code,
                    text,
                    is_final=is_final,
                    confidence=confidence
                )

                # If final, translate to other languages
                if is_final:
                    translations = await translation_service.translate_to_multiple(
                        text,
                        target_languages,
                        source_language=source_lang_code
                    )

                    # Broadcast translations
                    for lang, trans_result in translations.items():
                        if lang != source_lang_code:  # Don't re-broadcast source
                            await translation_manager.broadcast_subtitle(
                                event_id,
                                lang,
                                trans_result["translated_text"],
                                is_final=True,
                                confidence=confidence
                            )

        # Start transcription processing
        transcription_task = asyncio.create_task(process_transcriptions())

        # Receive audio chunks from broadcaster
        while True:
            data = await websocket.receive()

            if "bytes" in data:
                # Audio chunk
                audio_chunk = data["bytes"]
                await audio_queue.put(audio_chunk)

            elif "text" in data:
                # Control message
                try:
                    message = json.loads(data["text"])

                    if message.get("type") == "stop":
                        # Stop broadcasting
                        await audio_queue.put(None)  # Stop signal
                        break

                    elif message.get("type") == "ping":
                        await websocket.send_json({"type": "pong"})

                    elif message.get("type") == "set_languages":
                        # Update target languages
                        target_languages = message.get("languages", target_languages)

                except json.JSONDecodeError:
                    logger.warning("Invalid JSON from broadcaster")

    except WebSocketDisconnect:
        logger.info(f"Broadcaster disconnected from event {event_id}")

    finally:
        # Stop translation session
        translation_manager.stop_session(event_id)

        # Notify viewers
        await translation_manager.broadcast_to_all_languages(
            event_id,
            "translation_stopped",
            {}
        )

        # Cancel transcription task
        if 'transcription_task' in locals():
            transcription_task.cancel()

        await websocket.close()


# === REST API ENDPOINTS ===

@router.post("/events/{event_id}/start")
async def start_translation_session(
    event_id: str,
    source_language: str = "it",
    target_languages: List[str] = ["en", "es", "fr", "de"],
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(get_current_admin_user)
):
    """
    Start a translation session (admin only)

    This is a REST endpoint to initialize the session without WebSocket
    """
    # Validate event_id length
    if len(event_id) > 100:
        raise HTTPException(status_code=422, detail="Event ID too long")

    try:
        # Verify event exists
        result = await db.execute(
            select(LiveEvent).where(LiveEvent.id == event_id)
        )
        event = result.scalar_one_or_none()

        if not event:
            raise HTTPException(status_code=404, detail="Live event not found")

        # Start session
        translation_manager.start_session(event_id, source_language, target_languages)

        return {
            "message": "Translation session started",
            "event_id": event_id,
            "source_language": source_language,
            "target_languages": target_languages
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error starting translation session: {e}")
        raise HTTPException(status_code=404, detail="Live event not found")


@router.post("/events/{event_id}/stop")
async def stop_translation_session(
    event_id: str,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(get_current_admin_user)
):
    """Stop a translation session (admin only)"""
    translation_manager.stop_session(event_id)

    # Notify all viewers
    await translation_manager.broadcast_to_all_languages(
        event_id,
        "translation_stopped",
        {}
    )

    return {
        "message": "Translation session stopped",
        "event_id": event_id
    }


@router.get("/events/{event_id}/stats")
async def get_translation_stats(
    event_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Get translation statistics for an event

    Returns viewer count per language
    """
    import uuid as uuid_module
    import re

    # Validate event_id format - must be valid UUID or alphanumeric
    # Reject SQL injection attempts and special characters
    if not re.match(r'^[a-zA-Z0-9_-]+$', event_id):
        raise HTTPException(status_code=422, detail="Invalid event ID format")

    # Validate event_id length
    if len(event_id) > 100:
        raise HTTPException(status_code=422, detail="Event ID too long")

    # Check if event exists/is active
    if not translation_manager.is_session_active(event_id) and event_id not in translation_manager.active_sessions:
        raise HTTPException(status_code=404, detail="Event not found")

    stats = translation_manager.get_language_stats(event_id)
    total_viewers = translation_manager.get_viewer_count(event_id)

    return {
        "event_id": event_id,
        "is_active": translation_manager.is_session_active(event_id),
        "total_viewers": total_viewers,
        "language_stats": stats,
        "session_info": translation_manager.active_sessions.get(event_id, {})
    }


@router.get("/languages/supported")
async def get_supported_languages():
    """Get list of supported languages for speech and translation"""
    try:
        speech_service = get_speech_service()
        translation_service = get_translation_service()

        speech_langs = speech_service.get_supported_languages() if speech_service else []
        trans_langs = translation_service.get_supported_languages() if translation_service else []

        return {
            "speech_languages": speech_langs,
            "translation_languages": trans_langs
        }
    except Exception as e:
        logger.error(f"Error getting supported languages: {e}")
        # Return empty lists on error
        return {
            "speech_languages": [],
            "translation_languages": []
        }


@router.get("/providers/info")
async def get_providers_info():
    """
    Get information about current speech and translation providers

    Shows which provider is active and their features/costs
    """
    return get_provider_info()


@router.post("/providers/switch")
async def switch_service_provider(
    service_type: str,  # "speech" or "translation"
    provider: str,  # "whisper", "google", "nllb"
    admin: User = Depends(get_current_admin_user)
):
    """
    Switch service provider (admin only)

    Args:
        service_type: "speech" or "translation"
        provider: Provider name (whisper, google, nllb)

    Note:
        Requires application restart for full effect
    """
    # Validate service_type
    valid_service_types = ["speech", "translation"]
    if service_type not in valid_service_types:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid service_type. Must be one of: {valid_service_types}"
        )

    # Validate provider
    valid_providers = {
        "speech": ["whisper", "google", "azure"],
        "translation": ["nllb", "google", "deepl"]
    }
    if provider not in valid_providers.get(service_type, []):
        raise HTTPException(
            status_code=422,
            detail=f"Invalid provider for {service_type}. Must be one of: {valid_providers.get(service_type, [])}"
        )

    try:
        switch_provider(service_type, provider)
        return {
            "message": f"Provider switched to {provider}",
            "service_type": service_type,
            "provider": provider,
            "note": "Restart application for changes to take full effect"
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
