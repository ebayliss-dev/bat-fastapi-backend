import base64
from datetime import timedelta
import hashlib
from typing import List, Optional
import uuid
import os
import asyncio
import aiohttp
import logging
from logging.handlers import RotatingFileHandler

from werkzeug.security import check_password_hash
from fastapi import APIRouter, Body, Depends, HTTPException, Query, status, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr
from sqlalchemy import text
from sqlalchemy.orm import Session
from slowapi import Limiter
from slowapi.util import get_remote_address
import stripe
from jose import JWTError, jwt

from app import crud
from app.models.logs import Log
from app.models.user import User
from app.schemas.login import LoginRequest
from app.schemas.token import PasswordSubmitRequest, RefreshTokenRequest, Token
from app.utils import stripe_util
from ..database import get_db
from ..auth import (
    REFRESH_SECRET_KEY,
    create_access_token,
    create_refresh_token,
    get_current_active_user,
    ACCESS_TOKEN_EXPIRE_MINUTES,
    SECRET_KEY,
    ALGORITHM,
    get_current_user,
)

# ---------------------------------------------------------------------------
# Logger Setup
# ---------------------------------------------------------------------------
LOG_FILE = os.path.join(os.path.dirname(__file__), "../logs/auth.log")
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

logger = logging.getLogger("auth_logger")
logger.setLevel(logging.DEBUG)

# Rotating file handler (10MB max per file, 5 backups)
handler = RotatingFileHandler(LOG_FILE, maxBytes=10 * 1024 * 1024, backupCount=5, encoding='utf-8')
formatter = logging.Formatter(
    "%(asctime)s [%(levelname)s] [%(name)s:%(lineno)d] %(funcName)s(): %(message)s"
)
handler.setFormatter(formatter)
logger.addHandler(handler)

# ---------------------------------------------------------------------------
# Router and Limiter
# ---------------------------------------------------------------------------
router = APIRouter()
limiter = Limiter(key_func=get_remote_address)

class DashboardResponse(BaseModel):
    userFirstname: str
    userSurname: str
    userName: str
    userPoints: int
    userImage: Optional[str]
    userId: str
    totalPubs: int
    totalRatings: int
    totalCheckins: int
    totalCredits: int
    userRank: int
    teamRank: int | None = None
    teamScore: int | None = None
    totalBadges: int
    totalFavourites: int

@router.post("/info", response_model=DashboardResponse)
async def get_business_dashboard(
    search: Optional[str] = "",
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    current_user = db.query(User).filter_by(id=str(current_user.id)).first()

    return {
        'userId': str(current_user.id),
        'userFirstname': current_user.firstname,
        'userSurname': current_user.surname,
        'userName': current_user.user_name,
        'userPoints': current_user.credits,
        'userImage': str(current_user.image),
        'totalPubs': 15,
        'totalRatings': 0,
        'totalCheckins': 1,
        'totalCredits': str(current_user.credits),
        'userRank': 213,
        'teamRank': None,
        'teamScore': None,
        'totalFavourites': 1,
        'totalBadges': 13,
   }

class Advert(BaseModel):
    image: str
    url: Optional[str]

class AdvertResponse(BaseModel):
    adverts: List[Advert]


@router.get("/adverts", response_model=AdvertResponse)
async def get_adverts(db: Session = Depends(get_db)):

    query = text("""
        SELECT id, image, body
        FROM public.news
        ORDER BY id DESC
    """)
    
    rows = db.execute(query).fetchall()

    adverts = []

    for row in rows:
        # image is already VARCHAR base64 — no further encoding needed
        b64_image = row.image  

        adverts.append(
            Advert(
                image=b64_image,
                url=row.body
            )
        )

    return AdvertResponse(adverts=adverts)


class LogItem(BaseModel):
    message: str

class LogsResponse(BaseModel):
    logs: List[LogItem]
    
@router.get("/logs", response_model=LogsResponse)
async def get_latest_logs(db: Session = Depends(get_db)):
    rows = (
        db.query(Log)
        .order_by(Log.added.desc())
        .limit(3)
        .all()
    )

    return {
        "logs": [
            {
                "message": row.body,
                "timestamp": row.added.isoformat()
            }
            for row in rows
        ]
    }
