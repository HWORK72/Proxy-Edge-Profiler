import json
from collections import defaultdict
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from core.logger import app_logger

router: APIRouter = APIRouter(tags=["WebSockets"])


class ConnectionManager:
    def __init__(self) -> None:
        self._active_connections: dict[str, list[WebSocket]] = defaultdict(list)

    async def connect(self, session_id: str, websocket: WebSocket) -> None:
        await websocket.accept()
        self._active_connections[session_id].append(websocket)
        app_logger.debug(f"WebSocket client connected to session: {session_id}")

    def disconnect(self, session_id: str, websocket: WebSocket) -> None:
        if session_id in self._active_connections:
            if websocket in self._active_connections[session_id]:
                self._active_connections[session_id].remove(websocket)
            if not self._active_connections[session_id]:
                del self._active_connections[session_id]
        app_logger.debug(f"WebSocket client disconnected from session: {session_id}")

    async def broadcast_progress(self, session_id: str, payload: dict) -> None:
        if session_id not in self._active_connections:
            return

        serialized: str = json.dumps(payload)
        dead_sockets: list[WebSocket] = []

        for socket in self._active_connections[session_id]:
            try:
                await socket.send_text(serialized)
            except Exception as error:
                app_logger.debug(f"WebSocket send failure: {error}")
                dead_sockets.append(socket)

        for dead_socket in dead_sockets:
            self.disconnect(session_id, dead_socket)


ws_manager: ConnectionManager = ConnectionManager()


@router.websocket("/ws/scan/{session_id}")
async def websocket_scan_endpoint(websocket: WebSocket, session_id: str) -> None:
    await ws_manager.connect(session_id, websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(session_id, websocket)
    except Exception as error:
        app_logger.debug(f"WebSocket session error for {session_id}: {error}")
        ws_manager.disconnect(session_id, websocket)