"""
AI Vulnerability Scanner - FastAPI Backend
Production-grade defensive security testing tool
"""
import asyncio
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import uvicorn
import json

from backend.database import init_db
from backend.routes import router
from backend.auth_routes import router as auth_router
from backend.websocket_manager import ConnectionManager
from backend.config import settings

# Configure structured logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('scanner.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# WebSocket connection manager
manager = ConnectionManager()

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize and cleanup on startup/shutdown"""
    logger.info("Initializing AI Vulnerability Scanner...")
    await init_db()
    logger.info("Database initialized")
    yield
    logger.info("Shutting down...")

app = FastAPI(
    title="AI Vulnerability Scanner",
    description="Production-grade defensive security testing tool",
    version="1.0.0",
    lifespan=lifespan
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routes
app.include_router(auth_router, tags=["authentication"])
app.include_router(router, tags=["scanner"])

# WebSocket endpoint for real-time updates
@app.websocket("/ws/{scan_id}")
async def websocket_endpoint(websocket: WebSocket, scan_id: str):
    await manager.connect(websocket, scan_id)
    try:
        # Send initial connection message
        await websocket.send_text(json.dumps({
            "type": "connected",
            "scan_id": scan_id,
            "message": "WebSocket connected"
        }))
        # Keep connection alive
        while True:
            try:
                data = await websocket.receive_text()
                # Echo back to keep connection alive
                await websocket.send_text(json.dumps({"type": "pong"}))
            except:
                break
    except WebSocketDisconnect:
        manager.disconnect(scan_id)
        logger.info(f"WebSocket disconnected for scan {scan_id}")

# Serve frontend static files
from pathlib import Path

# Dashboard sections CSS is served via route below

frontend_path = Path(__file__).parent.parent / "frontend"
if frontend_path.exists():
    app.mount("/static", StaticFiles(directory=str(frontend_path)), name="static")

@app.get("/")
async def serve_frontend():
    frontend_file = Path(__file__).parent.parent / "frontend" / "index.html"
    if frontend_file.exists():
        return FileResponse(str(frontend_file))
    else:
        return {"error": "Frontend not found. Please ensure frontend/index.html exists."}

# Serve CSS and JS files
@app.get("/styles.css")
async def serve_css():
    css_file = Path(__file__).parent.parent / "frontend" / "styles.css"
    if css_file.exists():
        return FileResponse(str(css_file), media_type="text/css")
    raise HTTPException(status_code=404)

@app.get("/app.js")
async def serve_js():
    js_file = Path(__file__).parent.parent / "frontend" / "app.js"
    if js_file.exists():
        return FileResponse(str(js_file), media_type="application/javascript")
    raise HTTPException(status_code=404)

@app.get("/dashboard-sections.css")
async def serve_dashboard_css():
    css_file = Path(__file__).parent.parent / "frontend" / "dashboard-sections.css"
    if css_file.exists():
        return FileResponse(str(css_file), media_type="text/css")
    raise HTTPException(status_code=404)

if __name__ == "__main__":
    uvicorn.run(
        "backend.main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG,
        log_level="info"
    )

