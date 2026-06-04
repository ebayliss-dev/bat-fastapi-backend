import base64
from datetime import datetime, timedelta
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

async def image_to_bytes(value):
    if not value:
        return None

    # Already bytes
    if isinstance(value, bytes):
        return value

    # Full data URI, e.g. data:image/png;base64,...
    if isinstance(value, str) and value.startswith("data:image"):
        try:
            base64_part = value.split(",", 1)[1]
            return base64.b64decode(base64_part)
        except Exception as e:
            print(f"Failed to decode data URI image: {e}")
            return None

    # Image URL, e.g. https://pngclips.b-cdn.net/Kirkstall-ThreeSwords2021.png
    if isinstance(value, str) and value.startswith("http"):
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(value, timeout=10) as resp:
                    if resp.status != 200:
                        print(f"Image download failed: {resp.status} - {value}")
                        return None

                    return await resp.read()

        except Exception as e:
            print(f"Failed to download image URL {value}: {e}")
            return None

    # Raw base64 fallback
    if isinstance(value, str):
        try:
            return base64.b64decode(value)
        except Exception as e:
            print(f"Failed to decode raw base64 image: {e}")
            return None

    return None
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from typing import Any, Dict, Set

import aiohttp
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

# Make sure these imports match your project
# from app.database import get_db
# from app.models import Beer, Pub

router = APIRouter()


def normalise_text(value: Any) -> str:
    return str(value or "").strip()


def normalise_key_text(value: Any) -> str:
    return normalise_text(value).lower()


def normalise_abv_for_key(value: Any) -> str:
    """
    Keeps ABV matching stable between RAF payload values and DB Numeric values.

    Examples:
      4.2   -> 4.20
      4.20  -> 4.20
      None  -> ''
    """
    if value is None or value == "":
        return ""

    try:
        return str(Decimal(str(value)).quantize(Decimal("0.01")))
    except (InvalidOperation, ValueError, TypeError):
        return normalise_text(value)


def make_beer_key(brewery: Any, productname: Any, abv: Any) -> str:
    """
    Same idea as your /all beer grouping:
    brewery + productname + abv = one real beer.
    """
    return (
        f"{normalise_key_text(brewery)}|"
        f"{normalise_key_text(productname)}|"
        f"{normalise_abv_for_key(abv)}"
    )


def get_first(data: Dict[str, Any], *keys: str, default: Any = None) -> Any:
    """
    RAF payloads can be inconsistent, so this lets us support multiple possible field names.
    """
    for key in keys:
        value = data.get(key)
        if value is not None and value != "":
            return value
    return default


def parse_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value

    if value is None:
        return False

    return str(value).strip().lower() in {
        "true",
        "1",
        "yes",
        "y",
        "sold",
        "sold out",
        "sold-out",
    }


def is_sold_status(status: Any, sold_out: Any = None) -> bool:
    status_text = normalise_key_text(status)

    return (
        parse_bool(sold_out)
        or "sold" in status_text
        or "sold out" in status_text
        or "sold-out" in status_text
    )


def should_skip_beer(brewery: Any, productname: Any, ctype: Any = None) -> bool:
    """
    Keep your existing exclusion rules here.
    This example removes Thatchers and obvious cider entries.
    """
    brewery_text = normalise_key_text(brewery)
    product_text = normalise_key_text(productname)
    ctype_text = normalise_key_text(ctype)

    if "thatchers" in brewery_text:
        return True

    if "cider" in brewery_text or "cider" in product_text or "cider" in ctype_text:
        return True

    return False


@router.get("/sync")
async def sync_beers(db: Session = Depends(get_db)):
    """
    Sync beers from RealAleFinder.

    Important behaviour:
      - RAF beers currently returned are inserted/updated.
      - Existing beers for the same pub that are NOT returned anymore are NOT deleted.
      - Instead, those old beers are marked SOLD-OUT.
      - This lets users still rate historical beers, but prevents them showing as available.
    """

    pubs = db.query(Pub).all()
    token_map = {p.token: p.id for p in pubs if p.token}

    if not token_map:
        raise HTTPException(status_code=404, detail="No pub tokens found")

    token_string = ",".join(token_map.keys())
    url = f"https://www.realalefinder.com/beerboard/aggregate.php?tokens={token_string}"

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as resp:
                if resp.status != 200:
                    raise HTTPException(
                        status_code=resp.status,
                        detail="Upstream RealAleFinder error",
                    )

                payload = await resp.json()

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"RAF sync failed: {str(e)}")

    if "pubs" not in payload:
        raise HTTPException(status_code=500, detail="Invalid RealAleFinder format")

    imported_count = 0
    updated_count = 0
    marked_sold_out_count = 0
    skipped_count = 0

    now = datetime.now(timezone.utc)

    seen_keys_by_pub: Dict[Any, Set[str]] = {}

    try:
        for raf_pub in payload.get("pubs", []):
            token = get_first(raf_pub, "token", "pubtoken", "id", default=None)

            if token not in token_map:
                continue

            pub_id = token_map[token]
            seen_keys_by_pub.setdefault(pub_id, set())

            raf_beers = (
                raf_pub.get("beers")
                or raf_pub.get("beerboard")
                or raf_pub.get("products")
                or []
            )

            existing_pub_beers = db.query(Beer).filter(
                Beer.pub_id == pub_id
            ).all()

            existing_by_key = {
                make_beer_key(existing.brewery, existing.productname, existing.abv): existing
                for existing in existing_pub_beers
            }

            for item in raf_beers:
                brewery = get_first(item, "brewery", "breweryname", "producer", default="")
                productname = get_first(item, "productname", "name", "beer", "title", default="")
                abv = get_first(item, "abv", "strength", default=None)
                ctype = get_first(item, "ctype", "type", "category", default=None)

                if not brewery or not productname:
                    skipped_count += 1
                    continue

                if should_skip_beer(brewery, productname, ctype):
                    skipped_count += 1
                    continue

                beer_key = make_beer_key(brewery, productname, abv)
                seen_keys_by_pub[pub_id].add(beer_key)

                status = get_first(item, "status", "availability", default="Available")
                sold_out = is_sold_status(status, get_first(item, "sold_out", "soldout", default=False))

                beer = existing_by_key.get(beer_key)

                if beer is None:
                    beer = Beer(
                        pub_id=pub_id,
                        brewery=normalise_text(brewery),
                        productname=normalise_text(productname),
                        abv=Decimal(str(abv)).quantize(Decimal("0.01")) if abv not in [None, ""] else None,
                    )
                    db.add(beer)
                    imported_count += 1
                else:
                    updated_count += 1

                beer.brewery = normalise_text(brewery)
                beer.productname = normalise_text(productname)

                if abv not in [None, ""]:
                    try:
                        beer.abv = Decimal(str(abv)).quantize(Decimal("0.01"))
                    except Exception:
                        pass

                beer.status = "Sold Out" if sold_out else normalise_text(status or "Available")
                beer.sold_out = sold_out

                # If it appears in RAF again, it is not stale anymore.
                # If your model has these columns, they will be updated.
                if hasattr(beer, "last_seen_raf_at"):
                    beer.last_seen_raf_at = now

                if hasattr(beer, "removed_from_raf"):
                    beer.removed_from_raf = False

                if hasattr(beer, "updated_at"):
                    beer.updated_at = now

                # Existing fields from your /all endpoint.
                if hasattr(beer, "new"):
                    beer.new = parse_bool(get_first(item, "new", "is_new", default=False))

                if hasattr(beer, "pumpclip"):
                    beer.pumpclip = get_first(item, "pumpclip", "pump_clip", default=beer.pumpclip)

                if hasattr(beer, "pngpclip"):
                    beer.pngpclip = get_first(item, "pngpclip", "png_pclip", "image", "image_url", default=beer.pngpclip)

                if hasattr(beer, "tag"):
                    beer.tag = get_first(item, "tag", default=beer.tag)

                if hasattr(beer, "style"):
                    beer.style = get_first(item, "style", default=beer.style)

                if hasattr(beer, "stylecode"):
                    beer.stylecode = get_first(item, "stylecode", "style_code", default=beer.stylecode)

                if hasattr(beer, "colorfrom"):
                    beer.colorfrom = get_first(item, "colorfrom", "color_from", default=beer.colorfrom)

                if hasattr(beer, "colorto"):
                    beer.colorto = get_first(item, "colorto", "color_to", default=beer.colorto)

                if hasattr(beer, "shortstyledesc"):
                    beer.shortstyledesc = get_first(
                        item,
                        "shortstyledesc",
                        "short_style_desc",
                        default=beer.shortstyledesc,
                    )

                if hasattr(beer, "tastingnotes"):
                    beer.tastingnotes = get_first(
                        item,
                        "tastingnotes",
                        "tasting_notes",
                        "description",
                        default=beer.tastingnotes,
                    )

                if hasattr(beer, "price"):
                    price = get_first(item, "price", default=None)
                    if price not in [None, ""]:
                        try:
                            beer.price = Decimal(str(price))
                        except Exception:
                            pass

                if hasattr(beer, "ctype"):
                    beer.ctype = normalise_text(ctype or beer.ctype)

                if hasattr(beer, "allergens"):
                    beer.allergens = get_first(item, "allergens", default=beer.allergens)

                if hasattr(beer, "allergens_text"):
                    beer.allergens_text = get_first(
                        item,
                        "allergens_text",
                        "allergenstext",
                        default=beer.allergens_text,
                    )

            # IMPORTANT PART:
            # Anything already in our DB for this pub but missing from RAF now gets marked SOLD-OUT.
            seen_keys = seen_keys_by_pub.get(pub_id, set())

            for existing in existing_pub_beers:
                existing_key = make_beer_key(
                    existing.brewery,
                    existing.productname,
                    existing.abv,
                )

                if existing_key not in seen_keys:
                    already_sold = (
                        is_sold_status(existing.status, existing.sold_out)
                        or bool(getattr(existing, "sold_out", False))
                    )

                    existing.status = "Sold Out"
                    existing.sold_out = True

                    if hasattr(existing, "new"):
                        existing.new = False

                    if hasattr(existing, "removed_from_raf"):
                        existing.removed_from_raf = True

                    if hasattr(existing, "updated_at"):
                        existing.updated_at = now

                    if not already_sold:
                        marked_sold_out_count += 1

        db.commit()

    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Beer sync database update failed: {str(e)}")

    return {
        "success": True,
        "message": "Beer sync completed",
        "imported_count": imported_count,
        "updated_count": updated_count,
        "marked_sold_out_count": marked_sold_out_count,
        "skipped_count": skipped_count,
        "pubs_checked": len(seen_keys_by_pub),
    }


class BeerOut(RootModel[list[Dict[str, Any]]]):
    pass

from decimal import Decimal
from fastapi import Depends
from sqlalchemy import text
from sqlalchemy.orm import Session

# Keep your existing get_db import
# from app.database import get_db


def ordinal_label(n: int) -> str:
    if 10 <= n % 100 <= 20:
        suffix = "th"
    else:
        suffix = {1: "st", 2: "nd", 3: "rd"}.get(n % 10, "th")
    return f"{n}{suffix}"


@router.post("/all")
async def get_all_beers(db: Session = Depends(get_db)):
    """
    Returns one row per real beer, not one row per pub beer instance.

    Also returns pub_instances, which contains the exact beer row for each pub:
      - beer_id
      - pub_id
      - pub_name
      - status
      - sold_out
      - new
      - pngpclip
      - pumpclip

    This means:
      - beer list can still use grouped/ranked beers
      - pub page can filter pub_instances by pub_id and show the correct status
    """

    query = text("""
        WITH constants AS (
            SELECT
                10::numeric AS minimum_votes,
                20::numeric AS weighting_factor
        ),

        beer_instances AS (
            SELECT
                b.*,

                md5(
                    lower(trim(coalesce(b.brewery, ''))) || '|' ||
                    lower(trim(coalesce(b.productname, ''))) || '|' ||
                    coalesce(b.abv::text, '')
                ) AS beer_key

            FROM public.beers b
        ),

        beer_groups AS (
            SELECT
                bi.beer_key,

                -- Representative values for the grouped beer
                (ARRAY_AGG(bi.id ORDER BY bi.created_at DESC, bi.id DESC))[1] AS id,
                (ARRAY_AGG(bi.productname ORDER BY bi.created_at DESC, bi.id DESC))[1] AS productname,
                (ARRAY_AGG(bi.brewery ORDER BY bi.created_at DESC, bi.id DESC))[1] AS brewery,
                (ARRAY_AGG(bi.abv ORDER BY bi.created_at DESC, bi.id DESC))[1] AS abv,

                (ARRAY_AGG(bi.tag ORDER BY bi.created_at DESC, bi.id DESC))[1] AS tag,
                (ARRAY_AGG(bi.style ORDER BY bi.created_at DESC, bi.id DESC))[1] AS style,
                (ARRAY_AGG(bi.stylecode ORDER BY bi.created_at DESC, bi.id DESC))[1] AS stylecode,
                (ARRAY_AGG(bi.colorfrom ORDER BY bi.created_at DESC, bi.id DESC))[1] AS colorfrom,
                (ARRAY_AGG(bi.colorto ORDER BY bi.created_at DESC, bi.id DESC))[1] AS colorto,
                (ARRAY_AGG(bi.shortstyledesc ORDER BY bi.created_at DESC, bi.id DESC))[1] AS shortstyledesc,
                (ARRAY_AGG(bi.tastingnotes ORDER BY bi.created_at DESC, bi.id DESC))[1] AS tastingnotes,
                (ARRAY_AGG(bi.price ORDER BY bi.created_at DESC, bi.id DESC))[1] AS price,
                (ARRAY_AGG(bi.ctype ORDER BY bi.created_at DESC, bi.id DESC))[1] AS ctype,
                (ARRAY_AGG(bi.allergens ORDER BY bi.created_at DESC, bi.id DESC))[1] AS allergens,
                (ARRAY_AGG(bi.allergens_text ORDER BY bi.created_at DESC, bi.id DESC))[1] AS allergens_text,
                (ARRAY_AGG(bi.status ORDER BY bi.created_at DESC, bi.id DESC))[1] AS status,
                (ARRAY_AGG(bi.pngpclip ORDER BY bi.created_at DESC, bi.id DESC))[1] AS pngpclip,
                (ARRAY_AGG(bi.pumpclip ORDER BY bi.created_at DESC, bi.id DESC))[1] AS pumpclip,

                bool_or(COALESCE(bi.new, FALSE)) AS new,

                -- Group-level status helpers
                bool_and(COALESCE(bi.sold_out, FALSE)) AS sold_out,

                bool_or(
                    lower(coalesce(bi.status, '')) LIKE '%available%'
                    OR (
                        lower(coalesce(bi.status, '')) NOT LIKE '%coming%'
                        AND lower(coalesce(bi.status, '')) NOT LIKE '%sold%'
                        AND COALESCE(bi.sold_out, FALSE) = FALSE
                    )
                ) AS has_available_instance,

                bool_or(
                    lower(coalesce(bi.status, '')) LIKE '%coming%'
                ) AS has_coming_soon_instance,

                bool_or(
                    lower(coalesce(bi.status, '')) LIKE '%sold%'
                    OR COALESCE(bi.sold_out, FALSE) = TRUE
                ) AS has_sold_out_instance,

                ARRAY_AGG(DISTINCT COALESCE(p.name, 'Unknown Pub') ORDER BY COALESCE(p.name, 'Unknown Pub')) AS pubs_serving,
                ARRAY_AGG(DISTINCT bi.pub_id::text ORDER BY bi.pub_id::text) AS pub_ids,
                ARRAY_AGG(DISTINCT bi.id::text ORDER BY bi.id::text) AS beer_instance_ids,

                -- This is the important bit for the pub page.
                -- It preserves the exact beer row/status for each pub.
                JSONB_AGG(
                    DISTINCT JSONB_BUILD_OBJECT(
                        'beer_id', bi.id::text,
                        'pub_id', bi.pub_id::text,
                        'pub_name', COALESCE(p.name, 'Unknown Pub'),
                        'status', bi.status,
                        'sold_out', COALESCE(bi.sold_out, FALSE),
                        'new', COALESCE(bi.new, FALSE),
                        'pngpclip', bi.pngpclip,
                        'pumpclip', bi.pumpclip,
                        'created_at', bi.created_at
                    )
                ) AS pub_instances,

                ARRAY_AGG(DISTINCT COALESCE(p.name, 'Unknown Pub') ORDER BY COALESCE(p.name, 'Unknown Pub'))
                    FILTER (
                        WHERE lower(coalesce(bi.status, '')) LIKE '%available%'
                           OR (
                                lower(coalesce(bi.status, '')) NOT LIKE '%coming%'
                                AND lower(coalesce(bi.status, '')) NOT LIKE '%sold%'
                                AND COALESCE(bi.sold_out, FALSE) = FALSE
                           )
                    ) AS pubs_available,

                ARRAY_AGG(DISTINCT COALESCE(p.name, 'Unknown Pub') ORDER BY COALESCE(p.name, 'Unknown Pub'))
                    FILTER (
                        WHERE lower(coalesce(bi.status, '')) LIKE '%coming%'
                    ) AS pubs_coming_soon,

                ARRAY_AGG(DISTINCT COALESCE(p.name, 'Unknown Pub') ORDER BY COALESCE(p.name, 'Unknown Pub'))
                    FILTER (
                        WHERE lower(coalesce(bi.status, '')) LIKE '%sold%'
                           OR COALESCE(bi.sold_out, FALSE) = TRUE
                    ) AS pubs_sold_out,

                COUNT(DISTINCT bi.pub_id) AS locations,

                COUNT(DISTINCT bi.pub_id)
                    FILTER (
                        WHERE lower(coalesce(bi.status, '')) LIKE '%available%'
                           OR (
                                lower(coalesce(bi.status, '')) NOT LIKE '%coming%'
                                AND lower(coalesce(bi.status, '')) NOT LIKE '%sold%'
                                AND COALESCE(bi.sold_out, FALSE) = FALSE
                           )
                    ) AS available_locations,

                COUNT(DISTINCT bi.pub_id)
                    FILTER (
                        WHERE lower(coalesce(bi.status, '')) LIKE '%coming%'
                    ) AS coming_soon_locations,

                COUNT(DISTINCT bi.pub_id)
                    FILTER (
                        WHERE lower(coalesce(bi.status, '')) LIKE '%sold%'
                           OR COALESCE(bi.sold_out, FALSE) = TRUE
                    ) AS sold_out_locations

            FROM beer_instances bi
            LEFT JOIN public.pubs p ON p.id = bi.pub_id
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
                bg.pumpclip,
                bg.new,

                bg.sold_out,
                bg.has_available_instance,
                bg.has_coming_soon_instance,
                bg.has_sold_out_instance,

                bg.pubs_serving,
                bg.pub_ids,
                bg.beer_instance_ids,

                -- IMPORTANT: pass this through to the final response
                bg.pub_instances,

                bg.pubs_available,
                bg.pubs_coming_soon,
                bg.pubs_sold_out,

                bg.locations,
                bg.available_locations,
                bg.coming_soon_locations,
                bg.sold_out_locations,

                COALESCE(vs.vote_count, 0) AS vote_count,
                COALESCE(vs.avg_rating, 0) AS avg_rating,
                COALESCE(vs.min_rating, 0) AS min_rating,
                COALESCE(vs.max_rating, 0) AS max_rating,

                gs.global_avg,

                CASE
                    WHEN COALESCE(vs.vote_count, 0) >= c.minimum_votes THEN TRUE
                    ELSE FALSE
                END AS qualified,

                c.minimum_votes::int AS minimum_votes_required,
                c.weighting_factor::int AS weighting_factor,

                CASE
                    WHEN COALESCE(vs.vote_count, 0) = 0 THEN 0
                    ELSE ROUND(
                        (
                            (
                                COALESCE(vs.vote_count, 0)::numeric
                                * COALESCE(vs.avg_rating, 0)
                            )
                            +
                            (
                                c.weighting_factor * gs.global_avg
                            )
                        )
                        /
                        (
                            COALESCE(vs.vote_count, 0)::numeric
                            + c.weighting_factor
                        ),
                        3
                    )
                END AS weighted_score

            FROM beer_groups bg
            CROSS JOIN global_stats gs
            CROSS JOIN constants c
            LEFT JOIN vote_stats vs ON vs.beer_key = bg.beer_key
        ),

        ranked_beers AS (
            SELECT
                *,
                ROW_NUMBER() OVER (
                    ORDER BY
                        qualified DESC,
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

        for key, value in list(d.items()):
            if isinstance(value, Decimal):
                d[key] = float(value)

        d["id"] = str(d["id"])
        d["beer_key"] = str(d["beer_key"])

        d["pubs_serving"] = sorted(list(d["pubs_serving"] or []))
        d["pub_ids"] = sorted(list(d["pub_ids"] or []))
        d["beer_instance_ids"] = sorted(list(d["beer_instance_ids"] or []))

        # This is required for the pub page.
        d["pub_instances"] = d.get("pub_instances") or []

        d["pubs_available"] = sorted(list(d["pubs_available"] or []))
        d["pubs_coming_soon"] = sorted(list(d["pubs_coming_soon"] or []))
        d["pubs_sold_out"] = sorted(list(d["pubs_sold_out"] or []))

        d["locations"] = int(d["locations"] or 0)
        d["available_locations"] = int(d["available_locations"] or 0)
        d["coming_soon_locations"] = int(d["coming_soon_locations"] or 0)
        d["sold_out_locations"] = int(d["sold_out_locations"] or 0)

        d["vote_count"] = int(d["vote_count"] or 0)
        d["avg_rating"] = float(d["avg_rating"] or 0)
        d["min_rating"] = int(d["min_rating"] or 0)
        d["max_rating"] = int(d["max_rating"] or 0)

        d["global_avg"] = float(d["global_avg"] or 0)
        d["weighted_score"] = float(d["weighted_score"] or 0)

        d["qualified"] = bool(d["qualified"])
        d["minimum_votes_required"] = int(d["minimum_votes_required"] or 10)
        d["weighting_factor"] = int(d["weighting_factor"] or 20)

        d["sold_out"] = bool(d["sold_out"])
        d["has_available_instance"] = bool(d["has_available_instance"])
        d["has_coming_soon_instance"] = bool(d["has_coming_soon_instance"])
        d["has_sold_out_instance"] = bool(d["has_sold_out_instance"])

        d["new"] = bool(d["new"])
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