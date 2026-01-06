"""Authentication routes"""
from fastapi import APIRouter, HTTPException, Depends, status
from pydantic import BaseModel, EmailStr
from typing import Optional
import uuid
from datetime import datetime

from backend.auth import (
    get_password_hash, verify_password, create_access_token,
    get_user_by_username, get_user_by_email, get_current_active_user
)
from backend.database import User, async_session_maker
from sqlalchemy import select

router = APIRouter()

# Request/Response models
class UserSignup(BaseModel):
    username: str
    email: EmailStr
    password: str

class UserLogin(BaseModel):
    username: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str
    user: dict

class UserResponse(BaseModel):
    id: str
    username: str
    email: str
    full_name: Optional[str]
    created_at: str

@router.post("/api/auth/signup", response_model=UserResponse)
async def signup(user_data: UserSignup):
    """Register a new user"""
    try:
        # Check if username exists
        existing_user = await get_user_by_username(user_data.username)
        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Username already registered"
            )
        
        # Check if email exists
        existing_email = await get_user_by_email(user_data.email)
        if existing_email:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already registered"
            )
        
        # Create new user
        user_id = str(uuid.uuid4())
        hashed_password = get_password_hash(user_data.password)
        
        async with async_session_maker() as session:
            new_user = User(
                id=user_id,
                username=user_data.username,
                email=user_data.email,
                hashed_password=hashed_password,
                full_name=None,
                is_active=True
            )
            session.add(new_user)
            await session.commit()
            await session.refresh(new_user)
        
        return UserResponse(
            id=new_user.id,
            username=new_user.username,
            email=new_user.email,
            full_name=new_user.full_name,
            created_at=new_user.created_at.isoformat() if new_user.created_at else ""
        )
    except HTTPException:
        raise
    except Exception as e:
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"Signup error: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Internal server error: {str(e)}"
        )

@router.post("/api/auth/login", response_model=Token)
async def login(credentials: UserLogin):
    """Login and get access token"""
    user = await get_user_by_username(credentials.username)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Account not registered. Please sign up first."
        )
    
    if not verify_password(credentials.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect password. Please try again."
        )
    
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Inactive user"
        )
    
    # Update last login
    async with async_session_maker() as session:
        user.last_login = datetime.utcnow()
        session.add(user)
        await session.commit()
    
    # Create access token
    access_token = create_access_token(data={"sub": user.username})
    
    return Token(
        access_token=access_token,
        token_type="bearer",
        user={
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "full_name": user.full_name
        }
    )

@router.get("/api/auth/me", response_model=UserResponse)
async def get_current_user_info(current_user: User = Depends(get_current_active_user)):
    """Get current user information"""
    return UserResponse(
        id=current_user.id,
        username=current_user.username,
        email=current_user.email,
        full_name=current_user.full_name,
        created_at=current_user.created_at.isoformat() if current_user.created_at else ""
    )

@router.post("/api/auth/logout")
async def logout():
    """Logout (client should discard token)"""
    return {"message": "Successfully logged out"}

