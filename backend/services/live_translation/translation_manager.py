"""
🌐 Live Translation Manager
Manages WebSocket connections for real-time subtitle translation
"""

from fastapi import WebSocket, WebSocketDisconnect
from typing import Dict, Set, List, Optional
import json
import asyncio
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class TranslationConnectionManager:
    """Manages WebSocket connections for live translation subtitles"""

    def __init__(self):
        # Connections by event_id and language
        # Structure: {event_id: {language: Set[WebSocket]}}
        self.connections: Dict[str, Dict[str, Set[WebSocket]]] = {}

        # Active translation sessions
        # Structure: {event_id: {is_active: bool, source_language: str, available_languages: List[str]}}
        self.active_sessions: Dict[str, dict] = {}

    async def connect(self, event_id: str, language: str, websocket: WebSocket):
        """Accept new WebSocket connection for a specific language"""
        await websocket.accept()

        if event_id not in self.connections:
            self.connections[event_id] = {}

        if language not in self.connections[event_id]:
            self.connections[event_id][language] = set()

        self.connections[event_id][language].add(websocket)

        logger.info(
            f"Translation client connected - Event: {event_id}, "
            f"Language: {language}, "
            f"Total for this lang: {len(self.connections[event_id][language])}"
        )

        # Send welcome message with session info
        if event_id in self.active_sessions:
            await self.send_to_connection(websocket, {
                "type": "session_info",
                "event_id": event_id,
                "language": language,
                "source_language": self.active_sessions[event_id].get("source_language", "it"),
                "available_languages": self.active_sessions[event_id].get("available_languages", []),
                "is_active": self.active_sessions[event_id].get("is_active", False),
                "timestamp": datetime.utcnow().isoformat()
            })

    def disconnect(self, event_id: str, language: str, websocket: WebSocket):
        """Remove WebSocket connection"""
        if event_id in self.connections and language in self.connections[event_id]:
            self.connections[event_id][language].discard(websocket)

            # Clean up empty sets
            if not self.connections[event_id][language]:
                del self.connections[event_id][language]

            if not self.connections[event_id]:
                del self.connections[event_id]

        logger.info(
            f"Translation client disconnected - Event: {event_id}, Language: {language}"
        )

    async def send_to_connection(self, websocket: WebSocket, message: dict):
        """Send message to a specific WebSocket connection"""
        try:
            await websocket.send_json(message)
        except Exception as e:
            logger.error(f"Error sending message to connection: {e}")

    async def broadcast_subtitle(
        self,
        event_id: str,
        language: str,
        text: str,
        is_final: bool = False,
        confidence: Optional[float] = None
    ):
        """Broadcast subtitle to all connections for a specific language"""
        if event_id not in self.connections or language not in self.connections[event_id]:
            logger.warning(f"No connections for event {event_id} language {language}")
            return

        message = {
            "type": "subtitle",
            "event_id": event_id,
            "language": language,
            "text": text,
            "is_final": is_final,
            "confidence": confidence,
            "timestamp": datetime.utcnow().isoformat()
        }

        disconnected = []
        for connection in self.connections[event_id][language]:
            try:
                await connection.send_json(message)
            except Exception as e:
                logger.error(f"Error broadcasting subtitle: {e}")
                disconnected.append(connection)

        # Clean up disconnected clients
        for conn in disconnected:
            self.connections[event_id][language].discard(conn)

    async def broadcast_to_all_languages(
        self,
        event_id: str,
        message_type: str,
        data: dict
    ):
        """Broadcast a message to all language channels for an event"""
        if event_id not in self.connections:
            return

        message = {
            "type": message_type,
            "event_id": event_id,
            "data": data,
            "timestamp": datetime.utcnow().isoformat()
        }

        for language, connections in self.connections[event_id].items():
            disconnected = []
            for connection in connections:
                try:
                    await connection.send_json(message)
                except Exception as e:
                    logger.error(f"Error broadcasting to {language}: {e}")
                    disconnected.append(connection)

            # Clean up disconnected clients
            for conn in disconnected:
                connections.discard(conn)

    def start_session(
        self,
        event_id: str,
        source_language: str = "it",
        target_languages: Optional[List[str]] = None
    ):
        """Start a translation session for an event"""
        if target_languages is None:
            target_languages = ["en", "es", "fr", "de"]  # Default languages

        self.active_sessions[event_id] = {
            "is_active": True,
            "source_language": source_language,
            "available_languages": target_languages,
            "started_at": datetime.utcnow().isoformat()
        }

        logger.info(
            f"Translation session started - Event: {event_id}, "
            f"Source: {source_language}, Targets: {target_languages}"
        )

    def stop_session(self, event_id: str):
        """Stop a translation session"""
        if event_id in self.active_sessions:
            self.active_sessions[event_id]["is_active"] = False
            self.active_sessions[event_id]["ended_at"] = datetime.utcnow().isoformat()

            logger.info(f"Translation session stopped - Event: {event_id}")

    def get_viewer_count(self, event_id: str, language: Optional[str] = None) -> int:
        """Get number of viewers for an event (optionally filtered by language)"""
        if event_id not in self.connections:
            return 0

        if language:
            return len(self.connections[event_id].get(language, set()))

        # Total across all languages
        return sum(len(conns) for conns in self.connections[event_id].values())

    def get_language_stats(self, event_id: str) -> Dict[str, int]:
        """Get viewer count per language for an event"""
        if event_id not in self.connections:
            return {}

        return {
            lang: len(conns)
            for lang, conns in self.connections[event_id].items()
        }

    def is_session_active(self, event_id: str) -> bool:
        """Check if a translation session is active"""
        return (
            event_id in self.active_sessions and
            self.active_sessions[event_id].get("is_active", False)
        )


# Global translation manager instance
translation_manager = TranslationConnectionManager()


# Message builders
def subtitle_message(
    event_id: str,
    language: str,
    text: str,
    is_final: bool = False,
    confidence: Optional[float] = None
) -> dict:
    """Build subtitle message"""
    return {
        "type": "subtitle",
        "event_id": event_id,
        "language": language,
        "text": text,
        "is_final": is_final,
        "confidence": confidence,
        "timestamp": datetime.utcnow().isoformat()
    }


def translation_started(event_id: str, source_lang: str, target_langs: List[str]) -> dict:
    """Build translation started message"""
    return {
        "type": "translation_started",
        "event_id": event_id,
        "source_language": source_lang,
        "target_languages": target_langs,
        "timestamp": datetime.utcnow().isoformat()
    }


def translation_stopped(event_id: str) -> dict:
    """Build translation stopped message"""
    return {
        "type": "translation_stopped",
        "event_id": event_id,
        "timestamp": datetime.utcnow().isoformat()
    }


def language_stats_message(event_id: str, stats: Dict[str, int]) -> dict:
    """Build language stats message"""
    return {
        "type": "language_stats",
        "event_id": event_id,
        "stats": stats,
        "total_viewers": sum(stats.values()),
        "timestamp": datetime.utcnow().isoformat()
    }
