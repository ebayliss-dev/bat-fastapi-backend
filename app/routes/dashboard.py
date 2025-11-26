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
from app.models.beers import BeerVote
from app.models.logs import Log
from app.models.pubs import Pub
from app.models.user import User
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
    # ---------------- USER LOOKUP ---------------- #
    user = db.query(User).filter_by(id=str(current_user.id)).first()
    if not user:
        return {"error": "User not found"}

    # ---------------- ACTIVE EVENT ---------------- #
    event = db.execute(text("SELECT id FROM public.events WHERE isopen = true LIMIT 1")).mappings().first()
    if not event:
        return {"error": "No active event running"}

    event_id = str(event["id"])

    # ---------------- BEER VOTES ---------------- #
    votes = db.query(BeerVote).filter_by(user_id=str(user.id)).all()
    votes = len(votes)

    # ---------------- TEAM LOOKUP ---------------- #
    team_query = text("""
        SELECT id, name, user_ids, admin
        FROM public.teams
        WHERE :uid = ANY(string_to_array(user_ids, ',')::uuid[]);
    """)

    team = db.execute(team_query, {"uid": str(user.id)}).mappings().first()

    team_rank = None
    team_score = None

    # ========================================================= #
    # TEAM RANK + SCORE (only if user is in a team)
    # ========================================================= #
    if team:
        # 1) Team score
        team_score_query = text("""
            SELECT SUM(c.credits) AS total
            FROM public.credits c
            WHERE c.event_id = :eventId
              AND c.user_id = ANY(string_to_array(:members, ',')::uuid[]);
        """)
        

        team_score_row = db.execute(team_score_query, {
            "members": team["user_ids"],
            "eventId": event_id
        }).mappings().first()

        print(team_score_row)

        team_score = team_score_row["total"] or 0

        # 2) Team rank across all teams
        team_rank_query = text("""
    WITH team_totals AS (
        SELECT
            t.id AS team_id,
            COALESCE(SUM(c.credits), 0) AS total
        FROM public.teams t
        LEFT JOIN public.credits c 
          ON c.user_id = ANY(string_to_array(t.user_ids, ',')::uuid[])
         AND c.event_id = :eventId
        GROUP BY t.id
    ),
    ranked AS (
        SELECT
            team_id,
            total,
            RANK() OVER (ORDER BY total DESC) AS rank
        FROM team_totals
    )
    SELECT rank, team_id, total
    FROM ranked
    WHERE team_id = :teamId;
""")


        team_rank_row = db.execute(team_rank_query, {
            "teamId": str(team["id"]),
            "eventId": event_id
        }).mappings().first()

        team_rank = int(team_rank_row["rank"]) if team_rank_row else None

    # ========================================================= #
    # USER RANK FOR THIS EVENT (CREATE IF NONE)
    # ========================================================= #
    rank_query = text("""
        SELECT rank, user_id, credits FROM (
            SELECT
                user_id,
                credits,
                RANK() OVER (ORDER BY credits DESC) AS rank
            FROM public.credits
            WHERE event_id = :eventId
        ) ranked
        WHERE user_id = :uid;
    """)

    rank_row = db.execute(rank_query, {"uid": str(user.id), "eventId": event_id}).mappings().first()

    # No credits row? create one
    if not rank_row:
        new_id = str(uuid.uuid4())
        db.execute(text("""
            INSERT INTO public.credits (id, user_id, event_id, credits)
            VALUES (:id, :uid, :eventId, 0)
        """), {"id": new_id, "uid": str(user.id), "eventId": event_id})
        db.commit()

        return {
            "userId": str(user.id),
            "userFirstname": user.firstname,
            "userSurname": user.surname,
            "userName": user.user_name,
            "userPoints": 0,
            "userImage": str(user.image),
            "totalPubs": len(db.query(Pub).all()),
            "totalRatings": votes,
            "totalCheckins": 1,
            "totalCredits": "0",
            "userRank": 0,
            "teamRank": team_rank,
            "teamScore": team_score,
            "totalFavourites": 1,
            "totalBadges": 13,
        }

    # ========================================================= #
    # USER EXISTS → RETURN FULL DASHBOARD
    # ========================================================= #
    return {
        "userId": str(user.id),
        "userFirstname": user.firstname,
        "userSurname": user.surname,
        "userName": user.user_name,
        "userPoints": rank_row["credits"],
        "userImage": str(user.image),
        "totalPubs": len(db.query(Pub).all()),
        "totalRatings": votes,
        "totalCheckins": 1,
        "totalCredits": str(rank_row["credits"]),
        "userRank": int(rank_row["rank"]),
        "teamRank": team_rank,
        "teamScore": team_score,
        "totalFavourites": 1,
        "totalBadges": 13,
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
    timestamp: str
    image_base64: Optional[str] = None   # ⬅ added

class LogsResponse(BaseModel):
    logs: List[LogItem]


import base64

@router.get("/logs", response_model=LogsResponse)
async def get_latest_logs(db: Session = Depends(get_db)):
    rows = (
        db.query(Log)
        .order_by(Log.added.desc())
        .limit(100)
        .all()
    )

    return {
        "logs": [
            {
                "message": row.body,
                "timestamp": row.added.isoformat(),
                "image_base64": base64.b64encode(row.image).decode("utf-8") if row.image else None
            }
            for row in rows
        ]
    }
