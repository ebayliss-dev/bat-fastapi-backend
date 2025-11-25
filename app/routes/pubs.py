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
import stripe
from jose import JWTError, jwt

from app import crud
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

    class Config:
        from_attributes = True


@router.post("/all", response_model=List[PubOut])
async def get_all_pubs(
    db: Session = Depends(get_db),
):
    rows = db.execute(text("SELECT * FROM public.pubs ORDER BY index")).mappings().all()

    # Convert UUID → str
    normalised = []
    for row in rows:
        record = dict(row)
        record["id"] = str(record["id"]) if record["id"] else None
        normalised.append(record)

    return normalised


@router.post("/get")
def get_pub_by_id(payload: dict, db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    pub_id = payload.get("id")
    row = db.execute(text("SELECT * FROM public.pubs WHERE id = :id"), {"id": pub_id}).mappings().first()
    return row or {}
