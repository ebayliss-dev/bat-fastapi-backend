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
from pydantic import BaseModel, EmailStr, Field, RootModel
from sqlalchemy import and_, text
from sqlalchemy.orm import Session
from slowapi import Limiter
from slowapi.util import get_remote_address
import stripe
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




@router.post("/sync")
async def sync_beers(db: Session = Depends(get_db)):

    # 1. Load all pubs + tokens
    pubs = db.query(Pub).all()
    token_map = {p.token: p.id for p in pubs if p.token}

    if not token_map:
        raise HTTPException(404, "No pub tokens found")

    token_string = ",".join(token_map.keys())
    url = f"https://www.realalefinder.com/beerboard/aggregate.php?tokens={token_string}"

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
    seen = set()

    # 3. Loop through pubs
    for pub_entry in payload["pubs"]:
        token = pub_entry["token"]
        pub_id = token_map.get(token)
        if not pub_id:
            continue

        beers = pub_entry["data"].get("beerlist", [])

        for b in beers:

            # UNIQUE MATCHING RULE (no duplicates)
            existing = (
                db.query(Beer)
                .filter(
                    and_(
                        Beer.pub_id == pub_id,
                        Beer.productname == b["productname"],
                        Beer.brewery == b["brewery"]
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
                    brewery=b.get("brewery"),
                    productname=b.get("productname"),
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

    # 4. Set beers missing from API as sold out
    all_beers = db.query(Beer).all()
    for beer in all_beers:
        if beer.id not in seen:
            beer.sold_out = True
            beer.new = False

    db.commit()

    # 5. Return summary
    return {
        "status": "success",
        "pubs_processed": len(token_map),
        "imported": imported_count,
        "updated": updated_count,
        "total_changed": imported_count + updated_count,
    }



class BeerOut(RootModel[list[Dict[str, Any]]]):
    pass


@router.post("/all")
async def get_all_beers(db: Session = Depends(get_db)):
    query = text("""
        SELECT 
            b.id,
            b.productname,
            b.brewery,
            b.abv,
            b.tag,
            b.style,
            b.stylecode,
            b.colorfrom,
            b.colorto,
            b.shortstyledesc,
            b.tastingnotes,
            b.price,
            b.ctype,
            b.allergens,
            b.allergens_text,
            b.status,
            b.pngpclip,

            ARRAY_AGG(DISTINCT p.name) AS pubs_serving,
            ARRAY_AGG(DISTINCT p.id::text) AS pub_ids,
            COUNT(DISTINCT p.id) AS locations

        FROM public.beers b
        JOIN public.pubs p ON p.id = b.pub_id
        WHERE b.sold_out = FALSE
        GROUP BY b.id                 -- 🔥 THIS FIXES DUPLICATES
        ORDER BY locations DESC, productname ASC
    """)

    rows = db.execute(query).mappings().all()

    output = []
    for r in rows:
        d = dict(r)  # 🔥 make editable

        d["pubs_serving"] = sorted(list(r["pubs_serving"]))  # no duplicates
        d["pub_ids"]      = sorted(list(r["pub_ids"]))        # no duplicates
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

    # 2) Fetch all matching beers with the same product+brewery
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

    # 3) Split into serving vs sold-out
    pubs_serving = []
    pubs_sold_out = []

    for b in beers:
        entry = {
            "pub_id":  b["pub_id"],
            "pub_name": b["pub_name"],
            "status":  b["status"],    # 👈 IMPORTANT: per-pub status
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
    pub  = db.query(Pub).filter_by(name=payload.pub).first()

    if not beer:
        raise HTTPException(404, "Beer not found")
    if not pub:
        raise HTTPException(404, f"Pub '{payload.pub}' not found")

    # ============================================================
    # SAFE BASE64 → BYTEA HANDLING (NO MORE INVALID BASE64 ERRORS)
    # ============================================================
    image_bytes = None
    if payload.image_base64:
        try:
            img = payload.image_base64.strip()

            # Support URIs like: data:image/jpeg;base64,xxxxxx
            if img.startswith("data:"):
                img = img.split(",", 1)[1]

            image_bytes = b64decode(img)

        except Exception:
            raise HTTPException(400, "Invalid base64 image format")


    # Check if user's vote exists
    existing = db.execute(text("""
        SELECT id, rating 
        FROM public.beervotes 
        WHERE beer_id = :beer_id AND user_id = :user_id AND pub_id = :pub_id
        LIMIT 1
    """), {
        "beer_id": str(payload.beer_id),
        "user_id": str(user.id),
        "pub_id": str(pub.id)
    }).mappings().first()

    rating_str = f"{payload.rating}/5"   # ← new rating display format


    # =================================================================
    # 🆕 FIRST TIME VOTE — INSERT INTO beervotes + LOG
    # =================================================================
    if not existing:
        vote_id = str(uuid.uuid4())

        db.execute(text("""
            INSERT INTO public.beervotes (id, beer_id, pub_id, user_id, rating, created_at)
            VALUES (:id, :beer_id, :pub_id, :user_id, :rating, NOW())
        """), {
            "id": vote_id,
            "beer_id": str(payload.beer_id),
            "pub_id": str(pub.id),
            "user_id": str(user.id),
            "rating": payload.rating,
        })

        # Log: Rating (image stored if provided)
        db.execute(text("""
            INSERT INTO public.logs (uuid, body, added, image)
            VALUES (:id, :body, NOW(), :image)
        """), {
            "id": str(uuid.uuid4()),
            "body": f"{user.user_name} rated {beer.productname} at {pub.name} {rating_str}",
            "image": image_bytes
        })

        # Log: Review separately if provided
        if payload.review:
            db.execute(text("""
                INSERT INTO public.logs (uuid, body, added, image)
                VALUES (:id, :body, NOW(), NULL)
            """), {
                "id": str(uuid.uuid4()),
                "body": f'{user.user_name} reviewed {beer.productname} at {pub.name}, they said:\n"{payload.review}"'
            })

        db.commit()
        return {"success": True, "action": "new_rating", "rating": payload.rating}


    # =================================================================
    # 🔁 EXISTING VOTE — UPDATE RATING + LOG UPDATE
    # =================================================================
    db.execute(text("""
        UPDATE public.beervotes
        SET rating = :rating, updated_at = NOW()
        WHERE id = :id
    """), {
        "rating": payload.rating,
        "id": existing["id"]
    })

    # Log rating update (with image if supplied)
    db.execute(text("""
        INSERT INTO public.logs (uuid, body, added, image)
        VALUES (:id, :body, NOW(), :image)
    """), {
        "id": str(uuid.uuid4()),
        "body": f"{user.user_name} updated rating for {beer.productname} at {pub.name} to {rating_str}",
        "image": image_bytes
    })

    # Log review update if supplied
    if payload.review:
        db.execute(text("""
            INSERT INTO public.logs (uuid, body, added, image)
            VALUES (:id, :body, NOW(), NULL)
        """), {
            "id": str(uuid.uuid4()),
            "body": f'{user.user_name} reviewed {beer.productname} at {pub.name}, they said:\n"{payload.review}"'
        })

    db.commit()
    return {"success": True, "action": "updated_rating", "rating": payload.rating}
