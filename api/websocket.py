"""QAYAMAT — WebSocket Connection Manager"""

from fastapi import WebSocket
from typing import Dict


class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}

    async def connect(self, scan_id: str, websocket: WebSocket) -> None:
        await websocket.accept()
        self.active_connections[scan_id] = websocket

    def disconnect(self, scan_id: str) -> None:
        self.active_connections.pop(scan_id, None)

    async def send_message(self, scan_id: str, message: dict) -> None:
        ws = self.active_connections.get(scan_id)
        if ws:
            try:
                await ws.send_json(message)
            except Exception:
                self.disconnect(scan_id)

    async def broadcast(self, message: dict) -> None:
        dead = []
        for scan_id, ws in self.active_connections.items():
            try:
                await ws.send_json(message)
            except Exception:
                dead.append(scan_id)
        for scan_id in dead:
            self.disconnect(scan_id)


manager = ConnectionManager()
