"""Configuration settings"""
from pydantic_settings import BaseSettings
from typing import Optional

class Settings(BaseSettings):
    HOST: str = "127.0.0.1"
    PORT: int = 8000
    DEBUG: bool = False
    
    # Database
    DATABASE_URL: str = "sqlite+aiosqlite:///./scanner.db"
    
    # AI Configuration
    AI_ENABLED: bool = True
    AI_PROVIDER: str = "ollama"  # ollama, llama_cpp, huggingface
    OLLAMA_BASE_URL: str = "http://localhost:11434"
    OLLAMA_MODEL: str = "llama2"  # or mistral, codellama, etc.
    AI_FALLBACK_ENABLED: bool = True  # Use rule-based analysis if Ollama unavailable
    
    # Scanner Configuration
    MAX_CONCURRENT_SCANS: int = 5
    SCAN_TIMEOUT: int = 60  # seconds - reduced for faster scans
    PORT_SCAN_TIMEOUT: float = 0.5  # Faster port scanning
    
    # Security
    ALLOWED_IP_RANGES: list = [
        "127.0.0.1",
        "localhost",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16"
    ]
    
    class Config:
        env_file = ".env"
        case_sensitive = True

settings = Settings()

