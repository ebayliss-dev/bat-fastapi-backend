import base64
from datetime import timedelta
from decimal import Decimal
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
from pydantic import BaseModel, EmailStr, Field, RootModel
from sqlalchemy import and_, or_, text
from sqlalchemy.orm import Session
from slowapi import Limiter
from slowapi.util import get_remote_address
from jose import JWTError, jwt

from app import crud
from app.models.beers import Beer
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




@router.get("/sync")
async def sync_beers(db: Session = Depends(get_db)):

    # 1. Load all pubs + tokens
    pubs = db.query(Pub).all()
    token_map = {p.token: p.id for p in pubs if p.token}

    if not token_map:
        raise HTTPException(404, "No pub tokens found")

    token_string = ",".join(token_map.keys())
    url = f"https://www.realalefinder.com/beerboard/aggregate.php?tokens={token_string}"
    print(url)

    # 2. Fetch data
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as resp:
                if resp.status != 200:
                    raise HTTPException(resp.status, "Upstream RealAleFinder error")
                payload = await resp.json()
    except Exception as e:
        raise HTTPException(500, str(e))

    if "pubs" not in payload:
        raise HTTPException(500, "Invalid RealAleFinder format")

    imported_count = 0
    updated_count = 0
    deleted_cider_count = 0
    seen = set()

    # 3. Delete any existing ciders already in the DB
    existing_ciders = (
        db.query(Beer)
        .filter(
            or_(
                Beer.ctype.ilike("cider"),
                Beer.productname.ilike("%cider%")
            )
        )
        .all()
    )

    for cider in existing_ciders:
        db.delete(cider)
        deleted_cider_count += 1

    db.flush()

    # 4. Loop through pubs
    for pub_entry in payload["pubs"]:
        token = pub_entry.get("token")
        pub_id = token_map.get(token)

        if not pub_id:
            continue

        beers = pub_entry.get("data", {}).get("beerlist", [])

        for b in beers:

            ctype_check = (b.get("ctype") or "").strip().lower()
            productname_check = (b.get("productname") or "").strip().lower()

            # Skip ciders completely
            if ctype_check == "cider" or "cider" in productname_check:
                continue

            productname = b.get("productname")
            brewery = b.get("brewery")

            if not productname or not brewery:
                continue

            # UNIQUE MATCHING RULE - no duplicates
            existing = (
                db.query(Beer)
                .filter(
                    and_(
                        Beer.pub_id == pub_id,
                        Beer.productname == productname,
                        Beer.brewery == brewery
                    )
                )
                .first()
            )

            if existing:
                seen.add(existing.id)

                # Update beer
                existing.pumpclip = b.get("pumpclip")
                existing.pngpclip = b.get("pngpclip")
                existing.abv = b.get("abv")
                existing.tastingnotes = b.get("tastingnotes")
                existing.price = b.get("price")
                existing.tag = b.get("tag")
                existing.ctype = b.get("ctype")
                existing.style = b.get("style")
                existing.stylecode = b.get("stylecode")
                existing.colorfrom = b.get("colorfrom")
                existing.colorto = b.get("colorto")
                existing.shortstyledesc = b.get("shortstyledesc")
                existing.status = b.get("status")
                existing.allergens = b.get("allergens")
                existing.allergens_text = b.get("allergens_text")

                existing.sold_out = b.get("status") == "Sold Out"
                existing.new = False

                updated_count += 1

            else:
                # New beer
                beer = Beer(
                    pub_id=pub_id,
                    pumpclip=b.get("pumpclip"),
                    pngpclip=b.get("pngpclip"),
                    brewery=brewery,
                    productname=productname,
                    abv=b.get("abv"),
                    tastingnotes=b.get("tastingnotes"),
                    price=b.get("price"),
                    tag=b.get("tag"),
                    ctype=b.get("ctype"),
                    style=b.get("style"),
                    stylecode=b.get("stylecode"),
                    colorfrom=b.get("colorfrom"),
                    colorto=b.get("colorto"),
                    shortstyledesc=b.get("shortstyledesc"),
                    status=b.get("status"),
                    allergens=b.get("allergens"),
                    allergens_text=b.get("allergens_text"),
                    sold_out=b.get("status") == "Sold Out",
                    new=True
                )

                db.add(beer)
                db.flush()
                seen.add(beer.id)

                imported_count += 1

    # 5. Set beers missing from API as sold out
    all_beers = db.query(Beer).all()

    for beer in all_beers:
        if beer.id not in seen:
            beer.sold_out = True
            beer.new = False

    db.commit()

    # 6. Return summary
    return {
        "status": "success",
        "pubs_processed": len(token_map),
        "imported": imported_count,
        "updated": updated_count,
        "deleted_ciders": deleted_cider_count,
        "total_changed": imported_count + updated_count + deleted_cider_count,
    }


class BeerOut(RootModel[list[Dict[str, Any]]]):
    pass

from decimal import Decimal
from fastapi import Depends
from sqlalchemy import text
from sqlalchemy.orm import Session


def ordinal_label(n: int) -> str:
    if 10 <= n % 100 <= 20:
        suffix = "th"
    else:
        suffix = {1: "st", 2: "nd", 3: "rd"}.get(n % 10, "th")

    return f"{n}{suffix} Place"


@router.post("/all")
async def get_all_beers(db: Session = Depends(get_db)):
    """
    Returns one row per real beer, not one row per pub beer instance.

    A beer is treated as the same beer when:
      - brewery matches case-insensitively
      - productname matches case-insensitively
      - abv matches

    Votes are calculated at canonical beer level, not pub level.

    Ranking:
      - one latest vote per user per real beer
      - Bayesian weighted score for fairness
      - beers with no votes get score 0
      - backend returns rank and rank_label
    """

    query = text("""
        WITH beer_instances AS (
            SELECT
                b.*,

                md5(
                    lower(trim(coalesce(b.brewery, ''))) || '|' ||
                    lower(trim(coalesce(b.productname, ''))) || '|' ||
                    coalesce(b.abv::text, '')
                ) AS beer_key

            FROM public.beers b
            WHERE b.sold_out = FALSE
        ),

        beer_groups AS (
            SELECT
                bi.beer_key,

                -- Representative ID for frontend navigation
                (ARRAY_AGG(bi.id ORDER BY bi.created_at DESC))[1] AS id,

                (ARRAY_AGG(bi.productname ORDER BY bi.created_at DESC))[1] AS productname,
                (ARRAY_AGG(bi.brewery ORDER BY bi.created_at DESC))[1] AS brewery,
                (ARRAY_AGG(bi.abv ORDER BY bi.created_at DESC))[1] AS abv,

                (ARRAY_AGG(bi.tag ORDER BY bi.created_at DESC))[1] AS tag,
                (ARRAY_AGG(bi.style ORDER BY bi.created_at DESC))[1] AS style,
                (ARRAY_AGG(bi.stylecode ORDER BY bi.created_at DESC))[1] AS stylecode,
                (ARRAY_AGG(bi.colorfrom ORDER BY bi.created_at DESC))[1] AS colorfrom,
                (ARRAY_AGG(bi.colorto ORDER BY bi.created_at DESC))[1] AS colorto,
                (ARRAY_AGG(bi.shortstyledesc ORDER BY bi.created_at DESC))[1] AS shortstyledesc,
                (ARRAY_AGG(bi.tastingnotes ORDER BY bi.created_at DESC))[1] AS tastingnotes,
                (ARRAY_AGG(bi.price ORDER BY bi.created_at DESC))[1] AS price,
                (ARRAY_AGG(bi.ctype ORDER BY bi.created_at DESC))[1] AS ctype,
                (ARRAY_AGG(bi.allergens ORDER BY bi.created_at DESC))[1] AS allergens,
                (ARRAY_AGG(bi.allergens_text ORDER BY bi.created_at DESC))[1] AS allergens_text,
                (ARRAY_AGG(bi.status ORDER BY bi.created_at DESC))[1] AS status,
                (ARRAY_AGG(bi.pngpclip ORDER BY bi.created_at DESC))[1] AS pngpclip,

                bool_or(bi.new) AS new,

                ARRAY_AGG(DISTINCT p.name ORDER BY p.name) AS pubs_serving,
                ARRAY_AGG(DISTINCT p.id::text ORDER BY p.id::text) AS pub_ids,
                ARRAY_AGG(DISTINCT bi.id::text ORDER BY bi.id::text) AS beer_instance_ids,

                COUNT(DISTINCT p.id) AS locations

            FROM beer_instances bi
            JOIN public.pubs p ON p.id = bi.pub_id
            GROUP BY bi.beer_key
        ),

        raw_votes AS (
            SELECT
                bi.beer_key,
                v.id AS vote_id,
                v.user_id,
                v.rating,
                v.review,
                v.created_at,
                v.updated_at,

                ROW_NUMBER() OVER (
                    PARTITION BY bi.beer_key, v.user_id
                    ORDER BY coalesce(v.updated_at, v.created_at) DESC
                ) AS rn

            FROM public.beervotes v
            JOIN beer_instances bi ON bi.id = v.beer_id
            WHERE v.rating IS NOT NULL
        ),

        deduped_votes AS (
            SELECT
                beer_key,
                user_id,
                rating,
                review,
                created_at,
                updated_at
            FROM raw_votes
            WHERE rn = 1
        ),

        global_stats AS (
            SELECT
                COALESCE(AVG(rating), 0) AS global_avg
            FROM deduped_votes
        ),

        vote_stats AS (
            SELECT
                beer_key,
                COUNT(*) AS vote_count,
                ROUND(AVG(rating)::numeric, 2) AS avg_rating,
                MIN(rating) AS min_rating,
                MAX(rating) AS max_rating
            FROM deduped_votes
            GROUP BY beer_key
        ),

        scored_beers AS (
            SELECT
                bg.id,
                bg.beer_key,
                bg.productname,
                bg.brewery,
                bg.abv,
                bg.tag,
                bg.style,
                bg.stylecode,
                bg.colorfrom,
                bg.colorto,
                bg.shortstyledesc,
                bg.tastingnotes,
                bg.price,
                bg.ctype,
                bg.allergens,
                bg.allergens_text,
                bg.status,
                bg.pngpclip,
                bg.new,

                bg.pubs_serving,
                bg.pub_ids,
                bg.beer_instance_ids,
                bg.locations,

                COALESCE(vs.vote_count, 0) AS vote_count,
                COALESCE(vs.avg_rating, 0) AS avg_rating,
                COALESCE(vs.min_rating, 0) AS min_rating,
                COALESCE(vs.max_rating, 0) AS max_rating,

                CASE
                    WHEN COALESCE(vs.vote_count, 0) = 0 THEN 0
                    ELSE ROUND(
                        (
                            (
                                COALESCE(vs.vote_count, 0)::numeric
                                / (COALESCE(vs.vote_count, 0)::numeric + 3)
                            ) * COALESCE(vs.avg_rating, 0)
                        )
                        +
                        (
                            (
                                3::numeric
                                / (COALESCE(vs.vote_count, 0)::numeric + 3)
                            ) * gs.global_avg
                        ),
                        3
                    )
                END AS weighted_score

            FROM beer_groups bg
            CROSS JOIN global_stats gs
            LEFT JOIN vote_stats vs ON vs.beer_key = bg.beer_key
        ),

        ranked_beers AS (
            SELECT
                *,
                ROW_NUMBER() OVER (
                    ORDER BY
                        weighted_score DESC,
                        vote_count DESC,
                        avg_rating DESC,
                        locations DESC,
                        productname ASC
                ) AS rank
            FROM scored_beers
        )

        SELECT *
        FROM ranked_beers
        ORDER BY rank ASC;
    """)

    rows = db.execute(query).mappings().all()

    output = []

    for r in rows:
        d = dict(r)

        # Convert Decimal values for JSON
        for key, value in list(d.items()):
            if isinstance(value, Decimal):
                d[key] = float(value)

        d["id"] = str(d["id"])
        d["beer_key"] = str(d["beer_key"])

        d["pubs_serving"] = sorted(list(d["pubs_serving"] or []))
        d["pub_ids"] = sorted(list(d["pub_ids"] or []))
        d["beer_instance_ids"] = sorted(list(d["beer_instance_ids"] or []))

        d["locations"] = int(d["locations"] or 0)
        d["vote_count"] = int(d["vote_count"] or 0)
        d["avg_rating"] = float(d["avg_rating"] or 0)
        d["min_rating"] = int(d["min_rating"] or 0)
        d["max_rating"] = int(d["max_rating"] or 0)
        d["weighted_score"] = float(d["weighted_score"] or 0)

        d["rank"] = int(d["rank"] or 0)
        d["rank_label"] = ordinal_label(d["rank"])

        output.append(d)

    return output


@router.post("/get")
async def get_beer_by_id(payload: dict, db: Session = Depends(get_db)):

    # Extract ID from JSON body
    beer_id = payload.get("id")
    if not beer_id:
        raise HTTPException(status_code=400, detail="Beer ID missing")

    # 1) Fetch base beer by ID
    row = db.execute(
        text("SELECT * FROM public.beers WHERE id = :id"),
        {"id": beer_id}
    ).mappings().first()

    if not row:
        raise HTTPException(status_code=404, detail="Beer not found")

    base = dict(row)

    # Convert fields and rename created_at
    if base.get("id"):
        base["id"] = str(base["id"])
    if base.get("pub_id"):
        base["pub_id"] = str(base["pub_id"])
    if base.get("created_at"):
        base["added"] = str(base.pop("created_at"))

    base.setdefault("sold_out", False)
    base.setdefault("new", False)
    base.setdefault("archived", False)

    # 2) Fetch vote stats for this beer
    vote_stats = db.execute(
        text("""
            SELECT 
                COUNT(*) AS vote_count,
                COALESCE(AVG(rating), 0) AS average_rating
            FROM public.beervotes
            WHERE beer_id = :beer_id
        """),
        {"beer_id": beer_id}
    ).mappings().first()

    vote_count = int(vote_stats["vote_count"] or 0)
    average_rating = float(vote_stats["average_rating"] or 0)

    # Optional: round average rating to 1 decimal place
    average_rating = round(average_rating, 1)

    # 3) Fetch all matching beers with the same product+brewery
    beers = db.execute(
        text("""
            SELECT 
                b.id::text   AS beer_id,
                p.id::text   AS pub_id,
                p.name       AS pub_name,
                b.sold_out   AS sold_out,
                b.status     AS status
            FROM public.beers b
            JOIN public.pubs p ON p.id = b.pub_id
            WHERE b.productname = :product
              AND b.brewery     = :brewery
        """),
        {"product": base["productname"], "brewery": base["brewery"]}
    ).mappings().all()

    # 4) Split into serving vs sold-out
    pubs_serving = []
    pubs_sold_out = []

    for b in beers:
        entry = {
            "pub_id": b["pub_id"],
            "pub_name": b["pub_name"],
            "status": b["status"],
        }

        if b["sold_out"]:
            pubs_sold_out.append(entry)
        else:
            pubs_serving.append(entry)

    return {
        "beer": base,
        "pubs_serving": pubs_serving,
        "pubs_sold_out": pubs_sold_out,
        "locations": len(pubs_serving),
        "vote_count": vote_count,
        "average_rating": average_rating,
    }




class BeerVoteCreate(BaseModel):
    beer_id: str
    pub: str   # 🔥 accepts pub name instead of id
    rating: int = Field(..., ge=1, le=5)
    review: Optional[str] = None
    image_base64: Optional[str] = None

class BeerVoteResponse(BaseModel):
    id: str
    beer_id: str
    pub_id: str
    user_id: str
    rating: int
    review: Optional[str]
    created_at: str

    class Config:
        orm_mode = True


@router.post("/favourite")
def add_favourite(
    payload: dict,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    user = db.query(User).filter_by(id=str(current_user.id)).first()
    beer_id = payload.get("beer_id")
    action = payload.get("action")  # "add" or "remove"

    if not beer_id:
        raise HTTPException(status_code=400, detail="beer_id required")

    if action not in ["add", "remove"]:
        raise HTTPException(status_code=400, detail="action must be add/remove")


    # 🔥 Fetch beer name for log
    row = db.execute(
        text("SELECT productname FROM beers WHERE id = :id"),
        {"id": beer_id}
    ).mappings().first()

    beer_name = row["productname"] if row else "Unknown Beer"
    username = user.user_name or "Unknown User"


    # Build log text
    message = (
        f"{username} favourited {beer_name}"
        if action == "add"
        else f"{username} removed {beer_name} from favourites"
    )


    # 🔥 Insert into logs table
    db.execute(text("""
        INSERT INTO public.logs (uuid, body, added)
        VALUES (:id, :body, NOW())
    """), {
        "id": str(uuid.uuid4()),
        "body": message
    })

    db.commit()

    return {
        "status": "ok",
        "action": action,
        "beer_id": beer_id,
        "message": message
    }

from base64 import b64decode

@router.post("/rate")
async def rate_beer_by_id(
    payload: BeerVoteCreate,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    user = db.query(User).filter_by(id=str(current_user.id)).first()
    beer = db.query(Beer).filter_by(id=str(payload.beer_id)).first()
    pub = db.query(Pub).filter_by(name=payload.pub).first()

    if not user:
        raise HTTPException(404, "User not found")

    if not beer:
        raise HTTPException(404, "Beer not found")

    if not pub:
        raise HTTPException(404, f"Pub '{payload.pub}' not found")

    if payload.rating < 1 or payload.rating > 5:
        raise HTTPException(400, "Rating must be between 1 and 5")

    # ============================================================
    # SAFE BASE64 → BYTEA
    # ============================================================
    image_bytes = None

    if payload.image_base64:
        try:
            img = payload.image_base64.strip()

            if img.startswith("data:"):
                img = img.split(",", 1)[1]

            image_bytes = b64decode(img)

        except Exception:
            raise HTTPException(400, "Invalid base64 image format")

    rating_str = f"{payload.rating}/5"

    # ============================================================
    # BUILD CANONICAL BEER KEY
    # Same real beer = same brewery + same product name + same ABV
    # ============================================================
    beer_key_row = db.execute(text("""
        SELECT
            b.id,
            b.pub_id,
            b.productname,
            b.brewery,
            b.abv,
            md5(
                lower(trim(coalesce(b.brewery, ''))) || '|' ||
                lower(trim(coalesce(b.productname, ''))) || '|' ||
                coalesce(b.abv::text, '')
            ) AS beer_key
        FROM public.beers b
        WHERE b.id = :beer_id
        LIMIT 1
    """), {
        "beer_id": str(payload.beer_id)
    }).mappings().first()

    if not beer_key_row:
        raise HTTPException(404, "Beer not found")

    beer_key = beer_key_row["beer_key"]

    # ============================================================
    # CHECK EXISTING VOTE FOR SAME REAL BEER
    #
    # Important:
    # This checks all beer rows that have the same canonical beer key.
    # So if Bass exists at 5 pubs, the user only gets 1 vote for Bass.
    # ============================================================
    existing = db.execute(text("""
        WITH matching_beers AS (
            SELECT
                b.id,
                b.pub_id,
                md5(
                    lower(trim(coalesce(b.brewery, ''))) || '|' ||
                    lower(trim(coalesce(b.productname, ''))) || '|' ||
                    coalesce(b.abv::text, '')
                ) AS beer_key
            FROM public.beers b
            WHERE b.sold_out = FALSE
        )

        SELECT
            v.id,
            v.rating,
            v.beer_id,
            v.pub_id
        FROM public.beervotes v
        JOIN matching_beers mb ON mb.id = v.beer_id
        WHERE mb.beer_key = :beer_key
          AND v.user_id = :user_id
        ORDER BY coalesce(v.updated_at, v.created_at) DESC
        LIMIT 1
    """), {
        "beer_key": beer_key,
        "user_id": str(user.id)
    }).mappings().first()

    # ============================================================
    # NEW VOTE FOR THIS REAL BEER
    # ============================================================
    if not existing:
        vote_id = str(uuid.uuid4())

        db.execute(text("""
            INSERT INTO public.beervotes (
                id,
                beer_id,
                pub_id,
                user_id,
                rating,
                review,
                created_at,
                updated_at
            )
            VALUES (
                :id,
                :beer_id,
                :pub_id,
                :user_id,
                :rating,
                :review,
                NOW(),
                NOW()
            )
        """), {
            "id": vote_id,
            "beer_id": str(payload.beer_id),
            "pub_id": str(pub.id),
            "user_id": str(user.id),
            "rating": payload.rating,
            "review": payload.review
        })

        # ========================================================
        # LOG RATING
        # ========================================================
        db.execute(text("""
            INSERT INTO public.logs (
                uuid,
                body,
                added,
                image,
                user_id
            )
            VALUES (
                :id,
                :body,
                NOW(),
                :image,
                :user_id
            )
        """), {
            "id": str(uuid.uuid4()),
            "body": f"{user.user_name} rated {beer.productname} at {pub.name} {rating_str}",
            "image": image_bytes,
            "user_id": str(user.id)
        })

        # ========================================================
        # GIVE USER 100 CREDITS FOR FIRST VOTE ONLY
        # ========================================================
        db.execute(text("""
            UPDATE public.accounts
            SET credits = COALESCE(credits, 0) + 100
            WHERE id = :user_id
        """), {
            "user_id": str(user.id)
        })

        # ========================================================
        # LOG REVIEW
        # ========================================================
        if payload.review:
            db.execute(text("""
                INSERT INTO public.logs (
                    uuid,
                    body,
                    added,
                    image,
                    user_id
                )
                VALUES (
                    :id,
                    :body,
                    NOW(),
                    NULL,
                    :user_id
                )
            """), {
                "id": str(uuid.uuid4()),
                "body": f'{user.user_name} reviewed {beer.productname} at {pub.name}, they said:\n"{payload.review}"',
                "user_id": str(user.id)
            })

        db.commit()

        return {
            "success": True,
            "action": "new_rating",
            "rating": payload.rating,
            "beer_id": str(payload.beer_id),
            "pub_id": str(pub.id),
            "beer_key": beer_key,
            "credits_awarded": 100
        }

    # ============================================================
    # UPDATE EXISTING VOTE FOR SAME REAL BEER
    #
    # Important:
    # We update the existing vote rather than adding another vote.
    # We also move the vote to the currently selected pub/beer row,
    # so the log still reflects where the user rated it.
    # ============================================================
    db.execute(text("""
        UPDATE public.beervotes
        SET
            beer_id = :beer_id,
            pub_id = :pub_id,
            rating = :rating,
            review = :review,
            updated_at = NOW()
        WHERE id = :id
    """), {
        "beer_id": str(payload.beer_id),
        "pub_id": str(pub.id),
        "rating": payload.rating,
        "review": payload.review,
        "id": str(existing["id"])
    })

    # ============================================================
    # LOG RATING UPDATE
    # ============================================================
    db.execute(text("""
        INSERT INTO public.logs (
            uuid,
            body,
            added,
            image,
            user_id
        )
        VALUES (
            :id,
            :body,
            NOW(),
            :image,
            :user_id
        )
    """), {
        "id": str(uuid.uuid4()),
        "body": f"{user.user_name} updated rating for {beer.productname} at {pub.name} to {rating_str}",
        "image": image_bytes,
        "user_id": str(user.id)
    })

    # ============================================================
    # LOG REVIEW UPDATE
    # ============================================================
    if payload.review:
        db.execute(text("""
            INSERT INTO public.logs (
                uuid,
                body,
                added,
                image,
                user_id
            )
            VALUES (
                :id,
                :body,
                NOW(),
                NULL,
                :user_id
            )
        """), {
            "id": str(uuid.uuid4()),
            "body": f'{user.user_name} reviewed {beer.productname} at {pub.name}, they said:\n"{payload.review}"',
            "user_id": str(user.id)
        })

    db.commit()

    return {
        "success": True,
        "action": "updated_rating",
        "rating": payload.rating,
        "beer_id": str(payload.beer_id),
        "pub_id": str(pub.id),
        "beer_key": beer_key,
        "credits_awarded": 0
    }