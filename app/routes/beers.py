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


class BeerOut(BaseModel):
    id: str
    pub_id: Optional[str] = None
    name: str
    brewery: Optional[str] = None
    abv: Optional[str] = None
    tasting_notes: Optional[str] = None
    graphic: Optional[str] = None

    # NEW FIELDS
    archived: Optional[bool] = False
    sold_out: Optional[bool] = False
    new: Optional[bool] = False
    added: Optional[str] = None

    class Config:
        from_attributes = True



@router.post("/all", response_model=List[BeerOut])
async def get_all_beers(
    db: Session = Depends(get_db),
):
    rows = db.execute(text("SELECT * FROM public.beers")).mappings().all()

    normalised = []
    for row in rows:
        r = dict(row)

        # UUID → str
        r["id"] = str(r["id"]) if r["id"] else None
        r["pub_id"] = str(r["pub_id"]) if r.get("pub_id") else None

        # Ensure new booleans exist (DB defaults)
        r["archived"] = r.get("archived", False)
        r["sold_out"] = r.get("sold_out", False)
        r["new"] = r.get("new", False)

        # Convert timestamp → string
        if "added" in r and r["added"] is not None:
            r["added"] = str(r["added"])

        normalised.append(r)

    return normalised


@router.post("/get", response_model=BeerOut)
def get_beer_by_id(
    payload: dict,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    beer_id = payload.get("id")
    if not beer_id:
        raise HTTPException(status_code=400, detail="Beer ID missing")

    row = db.execute(
        text("SELECT * FROM public.beers WHERE id = :id"),
        {"id": beer_id}
    ).mappings().first()

    if not row:
        raise HTTPException(status_code=404, detail="Beer not found")

    r = dict(row)

    # UUID → string
    r["id"] = str(r["id"])
    r["pub_id"] = str(r["pub_id"]) if r.get("pub_id") else None

    # Convert timestamp → string
    if r.get("added"):
        r["added"] = str(r["added"])

    return r

