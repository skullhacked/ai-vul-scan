"""WebSocket connection manager for real-time updates"""
from fastapi import WebSocket
from typing import Dict, List
import json
import logging

logger = logging.getLogger(__name__)

class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, List[WebSocket]] = {}
    
    async def connect(self, websocket: WebSocket, scan_id: str):
        await websocket.accept()
        if scan_id not in self.active_connections:
            self.active_connections[scan_id] = []
        self.active_connections[scan_id].append(websocket)
        logger.info(f"WebSocket connected for scan {scan_id}")
    
    def disconnect(self, scan_id: str):
        if scan_id in self.active_connections:
            self.active_connections[scan_id] = [
                ws for ws in self.active_connections[scan_id]
                if ws.client_state.name != "DISCONNECTED"
            ]
            if not self.active_connections[scan_id]:
                del self.active_connections[scan_id]
    
    async def send_update(self, scan_id: str, data: dict):
        """Send update to all connections for a scan"""
        if scan_id in self.active_connections:
            message = json.dumps(data)
            disconnected = []
            for connection in self.active_connections[scan_id]:
                try:
                    await connection.send_text(message)
                except Exception as e:
                    logger.warning(f"Failed to send update: {e}")
                    disconnected.append(connection)
            
            # Remove disconnected connections
            for conn in disconnected:
                self.active_connections[scan_id].remove(conn)

