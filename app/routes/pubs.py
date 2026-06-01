import base64
from datetime import timedelta
import hashlib
from typing import Any, Dict, List, Optional
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
from jose import JWTError, jwt

from app import crud
from app.schemas.login import LoginRequest
from app.schemas.token import PasswordSubmitRequest, RefreshTokenRequest, Token
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
handler = RotatingFileHandler(
    LOG_FILE, maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8"
)
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


class PubOut(BaseModel):
    id: str
    name: str
    description: Optional[str] = None
    phone: Optional[str] = None
    landlord: Optional[str] = None
    manager: Optional[str] = None
    social1: Optional[str] = None
    social2: Optional[str] = None
    web: Optional[str] = None
    logo: Optional[str] = None
    photo1: Optional[str] = None
    photo2: Optional[str] = None
    longitude: Optional[str] = None
    latitude: Optional[str] = None
    opening_times: Optional[Dict[str, Any]] = None
    beer_board: Optional[str] = None

    # NEW FIELDS RETURNED BY QUERY:
    badges_count: int
    user_has_badge: bool

    class Config:
        from_attributes = True


@router.post("/all")
def get_all_pubs(
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    user_id = str(current_user.id)

    query = """
    WITH open_badges AS (
        SELECT 
            blu.pub_id,
            blu.user_id,
            blu.event_id
        FROM public.badges_link_user blu
        JOIN public.events e ON e.id = blu.event_id
        WHERE e.isopen = TRUE
    ),

    badge_counts AS (
        SELECT 
            pub_id,
            COUNT(*) AS badges_count
        FROM open_badges
        GROUP BY pub_id
    ),

    user_badges AS (
        SELECT 
            pub_id
        FROM open_badges
        WHERE user_id = :user_id
    )

    SELECT 
        p.*,
        COALESCE(b.badges_count, 0) AS badges_count,
        (ub.pub_id IS NOT NULL) AS user_has_badge
    FROM public.pubs p
    LEFT JOIN badge_counts b ON b.pub_id = p.id
    LEFT JOIN user_badges ub ON ub.pub_id = p.id
    WHERE p.id != :excluded_pub_id
    ORDER BY p.index ASC;
    """

    try:
        rows = db.execute(
            text(query),
            {
                "user_id": user_id,
                "excluded_pub_ids": [
                    "05ad023f-e798-4c0d-a79a-315c586871b4",
                    "03f59c8b-f58f-4b05-b7b6-b1bed902afec",
                    "2a7e2db1-ccef-49d8-98f6-18225f9806ee",
                ],
            },
        ).mappings().all()

        return rows

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Database query failed: {str(e)}"
        )


@router.post("/get")
def get_pub_by_id(
    payload: dict,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    pub_id = payload.get("id")
    row = (
        db.execute(text("SELECT * FROM public.pubs WHERE id = :id"), {"id": pub_id})
        .mappings()
        .first()
    )
    return row or {}
