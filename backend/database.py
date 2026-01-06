"""Database models and initialization"""
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import declarative_base
from sqlalchemy import Column, String, Integer, Float, DateTime, Text, JSON, Boolean
from datetime import datetime
from backend.config import settings

Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    
    id = Column(String, primary_key=True)
    username = Column(String, unique=True, nullable=False, index=True)
    email = Column(String, unique=True, nullable=False, index=True)
    hashed_password = Column(String, nullable=False)
    full_name = Column(String, nullable=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime, nullable=True)

class Scan(Base):
    __tablename__ = "scans"
    
    id = Column(String, primary_key=True)
    target = Column(String, nullable=False)
    status = Column(String, default="pending")  # pending, running, completed, failed
    created_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    risk_score = Column(Float, default=0.0)
    total_vulnerabilities = Column(Integer, default=0)
    authorized = Column(Boolean, default=False)

class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    
    id = Column(String, primary_key=True)
    scan_id = Column(String, nullable=False, index=True)
    title = Column(String, nullable=False)
    description = Column(Text)
    severity = Column(String, nullable=False)  # critical, high, medium, low, info
    category = Column(String, nullable=False)
    evidence = Column(JSON)
    recommendation = Column(Text)
    cwe_id = Column(String, nullable=True)
    owasp_category = Column(String, nullable=True)
    ai_analysis = Column(Text, nullable=True)
    discovered_at = Column(DateTime, default=datetime.utcnow)

# Database engine and session
engine = create_async_engine(
    settings.DATABASE_URL,
    echo=settings.DEBUG,
    future=True
)

async_session_maker = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False
)

async def init_db():
    """Initialize database tables"""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

async def get_db():
    """Get database session"""
    async with async_session_maker() as session:
        yield session

