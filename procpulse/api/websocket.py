"""WebSocket manager for real-time live telemetry streaming."""

import json
import logging
from typing import Set, Dict, Any
from fastapi import WebSocket

logger = logging.getLogger(__name__)


class ConnectionManager:
    """Manages active WebSocket client connections and broadcasts."""

    def __init__(self) -> None:
        """Initialize connection manager."""
        self.active_connections: Set[WebSocket] = set()

    async def connect(self, websocket: WebSocket) -> None:
        """Accept and register a new WebSocket connection.

        Args:
            websocket: Incoming WebSocket instance.
        """
        await websocket.accept()
        self.active_connections.add(websocket)
        logger.debug("WebSocket client connected. Active: %d", len(self.active_connections))

    def disconnect(self, websocket: WebSocket) -> None:
        """Unregister a disconnected WebSocket.

        Args:
            websocket: Disconnected WebSocket instance.
        """
        self.active_connections.discard(websocket)
        logger.debug("WebSocket client disconnected. Active: %d", len(self.active_connections))

    async def broadcast(self, message: Dict[str, Any]) -> None:
        """Broadcast a JSON message to all active WebSocket clients.

        Args:
            message: Telemetry dictionary payload.
        """
        if not self.active_connections:
            return

        dead_connections: Set[WebSocket] = set()
        for connection in list(self.active_connections):
            try:
                await connection.send_json(message)
            except Exception as e:
                logger.debug("Failed sending to client, scheduling removal: %s", e)
                dead_connections.add(connection)

        for dead in dead_connections:
            self.disconnect(dead)


# Global singleton manager
ws_manager = ConnectionManager()
