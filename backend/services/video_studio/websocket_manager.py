from fastapi import WebSocket, WebSocketDisconnect
from typing import Dict, Set, List, Optional
import json
import asyncio
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

class ConnectionManager:
    """Manages WebSocket connections for real-time updates"""

    def __init__(self):
        # Active connections by user/session
        self.active_connections: Dict[str, Set[WebSocket]] = {}
        # Connections by video_id for targeted updates
        self.video_connections: Dict[str, Set[WebSocket]] = {}
        # Connections by project_id
        self.project_connections: Dict[str, Set[WebSocket]] = {}

    async def connect(self, websocket: WebSocket, client_id: str):
        """Accept new WebSocket connection"""
        await websocket.accept()
        if client_id not in self.active_connections:
            self.active_connections[client_id] = set()
        self.active_connections[client_id].add(websocket)
        logger.info(f"Client {client_id} connected. Total connections: {self.get_total_connections()}")

    def disconnect(self, websocket: WebSocket, client_id: str):
        """Remove WebSocket connection"""
        if client_id in self.active_connections:
            self.active_connections[client_id].discard(websocket)
            if not self.active_connections[client_id]:
                del self.active_connections[client_id]

        # Remove from video connections
        for video_id, connections in list(self.video_connections.items()):
            connections.discard(websocket)
            if not connections:
                del self.video_connections[video_id]

        # Remove from project connections
        for project_id, connections in list(self.project_connections.items()):
            connections.discard(websocket)
            if not connections:
                del self.project_connections[project_id]

        logger.info(f"Client {client_id} disconnected. Total connections: {self.get_total_connections()}")

    def subscribe_to_video(self, websocket: WebSocket, video_id: str):
        """Subscribe connection to video updates"""
        if video_id not in self.video_connections:
            self.video_connections[video_id] = set()
        self.video_connections[video_id].add(websocket)
        logger.info(f"Connection subscribed to video {video_id}")

    def subscribe_to_project(self, websocket: WebSocket, project_id: str):
        """Subscribe connection to project updates"""
        if project_id not in self.project_connections:
            self.project_connections[project_id] = set()
        self.project_connections[project_id].add(websocket)
        logger.info(f"Connection subscribed to project {project_id}")

    async def send_personal_message(self, message: dict, websocket: WebSocket):
        """Send message to specific WebSocket"""
        try:
            await websocket.send_json(message)
        except Exception as e:
            logger.error(f"Error sending personal message: {e}")

    async def broadcast_to_client(self, message: dict, client_id: str):
        """Send message to all connections of a specific client"""
        if client_id in self.active_connections:
            disconnected = []
            for connection in self.active_connections[client_id]:
                try:
                    await connection.send_json(message)
                except Exception as e:
                    logger.error(f"Error broadcasting to client {client_id}: {e}")
                    disconnected.append(connection)

            # Clean up disconnected clients
            for conn in disconnected:
                self.active_connections[client_id].discard(conn)

    async def broadcast_to_video(self, message: dict, video_id: str):
        """Send message to all connections subscribed to a video"""
        if video_id in self.video_connections:
            disconnected = []
            for connection in self.video_connections[video_id]:
                try:
                    await connection.send_json(message)
                except Exception as e:
                    logger.error(f"Error broadcasting to video {video_id}: {e}")
                    disconnected.append(connection)

            # Clean up disconnected clients
            for conn in disconnected:
                self.video_connections[video_id].discard(conn)

    async def broadcast_to_project(self, message: dict, project_id: str):
        """Send message to all connections subscribed to a project"""
        if project_id in self.project_connections:
            disconnected = []
            for connection in self.project_connections[project_id]:
                try:
                    await connection.send_json(message)
                except Exception as e:
                    logger.error(f"Error broadcasting to project {project_id}: {e}")
                    disconnected.append(connection)

            # Clean up disconnected clients
            for conn in disconnected:
                self.project_connections[project_id].discard(conn)

    async def broadcast_all(self, message: dict):
        """Send message to all active connections"""
        disconnected = []
        for client_id, connections in self.active_connections.items():
            for connection in connections:
                try:
                    await connection.send_json(message)
                except Exception as e:
                    logger.error(f"Error broadcasting to all: {e}")
                    disconnected.append((client_id, connection))

        # Clean up disconnected clients
        for client_id, conn in disconnected:
            if client_id in self.active_connections:
                self.active_connections[client_id].discard(conn)

    def get_total_connections(self) -> int:
        """Get total number of active connections"""
        return sum(len(connections) for connections in self.active_connections.values())

    def get_video_subscribers(self, video_id: str) -> int:
        """Get number of connections subscribed to a video"""
        return len(self.video_connections.get(video_id, set()))

    def get_project_subscribers(self, project_id: str) -> int:
        """Get number of connections subscribed to a project"""
        return len(self.project_connections.get(project_id, set()))


# Global connection manager instance
manager = ConnectionManager()


# Message builders for common events
def build_message(event_type: str, data: dict, **kwargs) -> dict:
    """Build standardized WebSocket message"""
    return {
        "event": event_type,
        "data": data,
        "timestamp": datetime.utcnow().isoformat(),
        **kwargs
    }


def video_processing_started(video_id: str, filename: str) -> dict:
    """Message: video processing started"""
    return build_message("video_processing_started", {
        "video_id": video_id,
        "filename": filename,
        "status": "processing"
    })


def video_processing_progress(video_id: str, progress: int, stage: str) -> dict:
    """Message: video processing progress update"""
    return build_message("video_processing_progress", {
        "video_id": video_id,
        "progress": progress,
        "stage": stage
    })


def video_processing_completed(video_id: str, result: dict) -> dict:
    """Message: video processing completed"""
    return build_message("video_processing_completed", {
        "video_id": video_id,
        "status": "completed",
        "result": result
    })


def video_processing_failed(video_id: str, error: str) -> dict:
    """Message: video processing failed"""
    return build_message("video_processing_failed", {
        "video_id": video_id,
        "status": "failed",
        "error": error
    })


def skeleton_extraction_progress(video_id: str, frames_processed: int, total_frames: int) -> dict:
    """Message: skeleton extraction progress"""
    return build_message("skeleton_extraction_progress", {
        "video_id": video_id,
        "frames_processed": frames_processed,
        "total_frames": total_frames,
        "progress": int((frames_processed / total_frames) * 100) if total_frames > 0 else 0
    })


def technique_detected(video_id: str, technique: dict) -> dict:
    """Message: new technique detected"""
    return build_message("technique_detected", {
        "video_id": video_id,
        "technique": technique
    })


def project_updated(project_id: str, update_type: str, data: dict) -> dict:
    """Message: project update"""
    return build_message("project_updated", {
        "project_id": project_id,
        "update_type": update_type,
        "data": data
    })


def system_notification(message: str, level: str = "info") -> dict:
    """Message: system notification"""
    return build_message("system_notification", {
        "message": message,
        "level": level
    })
