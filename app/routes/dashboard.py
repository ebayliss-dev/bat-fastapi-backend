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
        WHERE image IS NOT NULL
          AND image <> ''
        ORDER BY RANDOM()
    """)

    rows = db.execute(query).mappings().all()

    adverts = []

    for row in rows:
        image_data = row["image"]

        if image_data.startswith("data:"):
            b64_image = image_data
        else:
            b64_image = f"data:image/jpeg;base64,{image_data}"

        adverts.append(
            Advert(
                image=b64_image,
                url=row["body"]
            )
        )

    return AdvertResponse(adverts=adverts)

class LogItem(BaseModel):
    id: str
    message: str
    timestamp: Optional[str]
    user_name: str
    image_base64: Optional[str] = None
    user_image_base64: Optional[str] = None
    like_count: int = 0
    comment_count: int = 0
    liked_by_me: bool = False


class LogsResponse(BaseModel):
    logs: List[LogItem]


@router.get("/logs", response_model=LogsResponse)
async def get_latest_logs(
    page: int = Query(1, ge=1),
    page_size: int = Query(10, ge=1, le=50),
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):

    # First page returns 3 only
    if page == 1:
        limit = 3
        offset = 0
    else:
        limit = page_size
        # Skip first 3, then paginate remaining
        offset = 3 + ((page - 2) * page_size)

    rows = (
        db.query(
            Log,
            User.user_name,
            User.image.label("user_image"),
            Pub.name.label("pub_name"),
        )
        .outerjoin(User, Log.user_id == User.id)
        .outerjoin(Pub, Log.user_id == Pub.id)
        .order_by(Log.added.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )

    def encode_image(value):
        if not value:
            return None

        if isinstance(value, str) and value.startswith("data:image"):
            return value

        if isinstance(value, str):
            return f"data:image/jpeg;base64,{value}"

        try:
            encoded = base64.b64encode(value).decode("utf-8")
            return f"data:image/png;base64,{encoded}"
        except Exception as e:
            print(f"Failed to encode image: {e}")
            return None

    logs = []
    current_user_id = str(current_user.id)

    for log, user_name, user_image, pub_name in rows:
        log_id = str(log.uuid)

        display_name = user_name or pub_name or "Unknown"
        display_image = log.image or user_image

        like_count = db.execute(
            text("""
                SELECT COUNT(*)
                FROM public.log_likes
                WHERE log_id = :log_id
            """),
            {"log_id": log_id}
        ).scalar() or 0

        comment_count = db.execute(
            text("""
                SELECT COUNT(*)
                FROM public.log_comments
                WHERE log_id = :log_id
            """),
            {"log_id": log_id}
        ).scalar() or 0

        liked_by_me = db.execute(
            text("""
                SELECT 1
                FROM public.log_likes
                WHERE log_id = :log_id
                  AND user_id = :user_id
                LIMIT 1
            """),
            {
                "log_id": log_id,
                "user_id": current_user_id,
            }
        ).first() is not None

        logs.append(
            {
                "id": log_id,
                "message": log.body,
                "timestamp": log.added.isoformat() if log.added else None,
                "user_name": display_name,
                "image_base64": encode_image(display_image),
                "user_image_base64": encode_image(display_image),
                "like_count": int(like_count),
                "comment_count": int(comment_count),
                "liked_by_me": liked_by_me,
            }
        )

    return {
        "logs": logs
    }

class LikeResponse(BaseModel):
    liked: bool
    like_count: int


@router.post("/logs/{log_id}/like", response_model=LikeResponse)
async def toggle_log_like(
    log_id: str,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    user_id = str(current_user.id)

    log_exists = db.execute(
        text("""
            SELECT uuid
            FROM public.logs
            WHERE uuid = :log_id
        """),
        {"log_id": log_id}
    ).mappings().first()

    if not log_exists:
        raise HTTPException(
            status_code=404,
            detail="Post not found"
        )

    existing_like = db.execute(
        text("""
            SELECT id
            FROM public.log_likes
            WHERE log_id = :log_id
              AND user_id = :user_id
        """),
        {
            "log_id": log_id,
            "user_id": user_id,
        }
    ).mappings().first()

    if existing_like:
        db.execute(
            text("""
                DELETE FROM public.log_likes
                WHERE log_id = :log_id
                  AND user_id = :user_id
            """),
            {
                "log_id": log_id,
                "user_id": user_id,
            }
        )
        liked = False
    else:
        db.execute(
            text("""
                INSERT INTO public.log_likes (log_id, user_id)
                VALUES (:log_id, :user_id)
                ON CONFLICT (log_id, user_id) DO NOTHING
            """),
            {
                "log_id": log_id,
                "user_id": user_id,
            }
        )
        liked = True

    db.commit()

    like_count = db.execute(
        text("""
            SELECT COUNT(*)
            FROM public.log_likes
            WHERE log_id = :log_id
        """),
        {"log_id": log_id}
    ).scalar() or 0

    return {
        "liked": liked,
        "like_count": int(like_count),
    }


class CommentCreate(BaseModel):
    body: str


class CommentItem(BaseModel):
    id: str
    body: str
    added: Optional[str]
    user_id: str
    user_name: str
    user_image_base64: Optional[str] = None


class CommentsResponse(BaseModel):
    comments: List[CommentItem]


@router.get("/logs/{log_id}/comments", response_model=CommentsResponse)
async def get_log_comments(
    log_id: str,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    log_exists = db.execute(
        text("""
            SELECT uuid
            FROM public.logs
            WHERE uuid = :log_id
        """),
        {"log_id": log_id}
    ).mappings().first()

    if not log_exists:
        raise HTTPException(
            status_code=404,
            detail="Post not found"
        )

    rows = db.execute(
        text("""
            SELECT
                c.id,
                c.body,
                c.added,
                c.user_id,
                u.user_name,
                u.image AS user_image
            FROM public.log_comments c
            LEFT JOIN public.accounts u
              ON u.id = c.user_id
            WHERE c.log_id = :log_id
            ORDER BY c.added ASC
        """),
        {"log_id": log_id}
    ).mappings().all()

    def encode_image(value):
        if not value:
            return None

        if isinstance(value, str) and value.startswith("data:image"):
            return value

        if isinstance(value, str):
            return f"data:image/jpeg;base64,{value}"

        try:
            encoded = base64.b64encode(value).decode("utf-8")
            return f"data:image/jpeg;base64,{encoded}"
        except Exception:
            return None

    comments = []

    for row in rows:
        comments.append(
            {
                "id": str(row["id"]),
                "body": row["body"],
                "added": row["added"].isoformat() if row["added"] else None,
                "user_id": str(row["user_id"]),
                "user_name": row["user_name"] or "Unknown",
                "user_image_base64": encode_image(row["user_image"]),
            }
        )

    return {
        "comments": comments
    }


@router.post("/logs/{log_id}/comments")
async def create_log_comment(
    log_id: str,
    payload: CommentCreate,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    user_id = str(current_user.id)
    body = payload.body.strip()

    if not body:
        raise HTTPException(
            status_code=400,
            detail="Comment cannot be empty"
        )

    if len(body) > 1000:
        raise HTTPException(
            status_code=400,
            detail="Comment is too long"
        )

    log_exists = db.execute(
        text("""
            SELECT uuid
            FROM public.logs
            WHERE uuid = :log_id
        """),
        {"log_id": log_id}
    ).mappings().first()

    if not log_exists:
        raise HTTPException(
            status_code=404,
            detail="Post not found"
        )

    row = db.execute(
        text("""
            INSERT INTO public.log_comments (log_id, user_id, body)
            VALUES (:log_id, :user_id, :body)
            RETURNING id, body, added, user_id
        """),
        {
            "log_id": log_id,
            "user_id": user_id,
            "body": body,
        }
    ).mappings().first()

    db.commit()

    comment_count = db.execute(
        text("""
            SELECT COUNT(*)
            FROM public.log_comments
            WHERE log_id = :log_id
        """),
        {"log_id": log_id}
    ).scalar() or 0

    return {
        "ok": True,
        "comment": {
            "id": str(row["id"]),
            "body": row["body"],
            "added": row["added"].isoformat() if row["added"] else None,
            "user_id": str(row["user_id"]),
        },
        "comment_count": int(comment_count),
    }

@router.get("/leaderboard")
def get_leaderboard(
    page: int = Query(1, ge=1),
    page_size: int = Query(8, ge=1, le=50),
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    offset = (page - 1) * page_size

    query = text("""
        WITH ranked AS (
            SELECT 
                u.id,
                u.user_name,
                COALESCE(u.credits, 0) AS credits,
                u.image,
                ROW_NUMBER() OVER (ORDER BY COALESCE(u.credits, 0) DESC) AS rank
            FROM public.accounts u
        )
        SELECT *
        FROM ranked
        WHERE rank > :offset
        ORDER BY rank
        LIMIT :limit
    """)

    result = db.execute(
        query,
        {"limit": page_size, "offset": offset}
    ).mappings().all()

    leaderboard = []

    for row in result:

        image_base64 = None

        if row["image"]:
            if isinstance(row["image"], bytes):
                image_base64 = base64.b64encode(row["image"]).decode("utf-8")
            else:
                image_base64 = row["image"]

        leaderboard.append({
            "id": str(row["id"]),
            "user_name": row["user_name"],
            "credits": row["credits"],
            "rank": row["rank"],  # 👈 THIS NOW CONTINUES PROPERLY
            "user_image_base64": image_base64
        })

    # total count
    total = db.execute(text("SELECT COUNT(*) FROM public.accounts")).scalar()
    has_more = offset + page_size < total

    return {
        "users": leaderboard,
        "page": page,
        "has_more": has_more,
        "current_user_id": str(current_user.id)
    }


class WaitlistRequest(BaseModel):
    email: EmailStr


@router.post("/waitlist")
async def waitlist(data: WaitlistRequest, db: Session = Depends(get_db)):

    email = data.email.lower().strip()

    # Check if already registered
    existing = db.execute(
        text("SELECT id FROM public.waitlist WHERE email = :email"),
        {"email": email}
    ).fetchone()

    if existing:
        return {"ok": True}  # already on list, don't error

    # Insert email
    db.execute(
        text("""
            INSERT INTO public.waitlist (email)
            VALUES (:email)
        """),
        {"email": email}
    )

    db.commit()

    return {"ok": True}