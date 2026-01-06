#!/usr/bin/env python3
"""
Startup script for AI Vulnerability Scanner
"""
import uvicorn
from backend.config import settings

if __name__ == "__main__":
    print("=" * 60)
    print("  AI VULNERABILITY SCANNER")
    print("  Production-Grade Defensive Security Testing Tool")
    print("=" * 60)
    print(f"\nStarting server on http://{settings.HOST}:{settings.PORT}")
    print(f"AI Analysis: {'Enabled' if settings.AI_ENABLED else 'Disabled'}")
    if settings.AI_ENABLED:
        print(f"AI Provider: {settings.AI_PROVIDER}")
        print(f"AI Model: {settings.OLLAMA_MODEL}")
    print("\nPress CTRL+C to stop\n")
    
    uvicorn.run(
        "backend.main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG,
        log_level="info"
    )

