import json
import logging
import os
import time
import redis
from sqlalchemy.orm import Session

LOG_FILE = os.path.join(os.path.dirname(__file__), "../logs/timeslots.log")
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger(__name__)

HOLD_QUEUE_KEY = "timeslot_hold_queue"
SOFT_HOLD_TTL = 300  # seconds
_redis_client: redis.Redis | None = None


def get_redis_client() -> redis.Redis:
    global _redis_client
    if _redis_client is None:
        host = os.getenv("REDIS_HOST", "redis")
        port = int(os.getenv("REDIS_PORT", "6379"))
        _redis_client = redis.Redis(host=host, port=port, db=0, decode_responses=True)
        try:
            _redis_client.ping()
        except Exception as e:
            logger.exception(f"[INIT] Redis connection failed: {e}")
    return _redis_client


# ---------------------------------------------------------------------------
# HOLD LOGIC
# ---------------------------------------------------------------------------
def hold_timeslot_logic(
    db: Session,
    business_id: str,
    date: str,
    time_str: str,
    pets_count: int,
    user_id: str,
    product_id: str,
    pet_id: str,
) -> bool:
    """
    Creates a new hold entry per pet_id if no existing hold exists
    for the same pet_id + date + time + product_id combination.
    Automatically ignores duplicates.
    """
    r = get_redis_client()

    if not pet_id:
        logger.warning("[HOLD] 🚫 No pet_id provided — skipping hold creation.")
        return False

    hold_data = {
        "business_id": str(business_id),
        "date": str(date),
        "time": str(time_str),
        "product_id": str(product_id),
        "user_id": str(user_id),
        "pet_id": str(pet_id),
        "pets_count": int(pets_count),
        "timestamp": int(time.time()),
        "expires_in": SOFT_HOLD_TTL,
    }

    try:
        # 🔍 Check existing holds before adding
        existing = r.lrange(HOLD_QUEUE_KEY, 0, -1)
        for raw in existing:
            try:
                obj = json.loads(raw)
                if (
                    obj.get("pet_id") == pet_id
                    and obj.get("product_id") == product_id
                    and obj.get("date") == date
                    and obj.get("time") == time_str
                ):
                    logger.info(
                        f"[HOLD] ⚠️ Duplicate hold skipped for pet={pet_id}, "
                        f"date={date}, time={time_str}, product={product_id}"
                    )
                    return True
            except Exception as e:
                logger.debug(f"[HOLD] ⚠️ Failed to parse hold entry: {e}")

        # ✅ Add new hold (unique)
        r.lpush(HOLD_QUEUE_KEY, json.dumps(hold_data))
        r.expire(HOLD_QUEUE_KEY, SOFT_HOLD_TTL)

        logger.info(
            f"[HOLD] ✅ Created NEW hold for biz={business_id}, user={user_id}, "
            f"pet={pet_id}, product={product_id}, time={time_str}"
        )
        logger.debug(f"[HOLD] Entry details: {json.dumps(hold_data, indent=2)}")
        return True

    except Exception as e:
        logger.exception(f"[HOLD] ❌ Failed to create hold: {e}")
        return False


# ---------------------------------------------------------------------------
# RELEASE LOGIC
# ---------------------------------------------------------------------------
def release_timeslot_logic(
    db: Session,
    business_id: str,
    date: str,
    time_str: str,
    pets_count: int,
    user_id: str,
    product_id: str,
    pet_id: str | None = None,
):
    return
    """
    Remove ONLY the exact matching hold entry (business_id + product_id + user_id + pet_id + time + date).
    Prevents other pets for the same user from being removed.
    """
    user_id = str(user_id)
    pet_id = str(pet_id) if pet_id not in (None, "None", "", "null") else None
    r = get_redis_client()

    logger.debug(
        f"[RELEASE] Attempting release for biz={business_id}, product={product_id}, "
        f"user={user_id}, pet={pet_id}, date={date}, time={time_str}"
    )

    try:
        items = r.lrange(HOLD_QUEUE_KEY, 0, -1)
        kept: list[str] = []
        removed_count = 0

        for i, raw in enumerate(items):
            try:
                obj = json.loads(raw)

                # Normalize
                o_pet = obj.get("pet_id")
                o_pet = None if o_pet in (None, "None", "", "null") else str(o_pet)

                if (
                    obj.get("business_id") == business_id
                    and obj.get("product_id") == product_id
                    and obj.get("user_id") == user_id
                    and obj.get("time") == time_str
                    and obj.get("date") == date
                    and o_pet == pet_id
                ):
                    removed_count += 1
                    logger.debug(f"[RELEASE] ✅ Match -> removing {obj}")
                else:
                    kept.append(raw)

            except Exception as e:
                logger.warning(f"[RELEASE] Could not parse item #{i}: {e}")
                kept.append(raw)

        # Write back kept entries only
        r.delete(HOLD_QUEUE_KEY)
        if kept:
            r.rpush(HOLD_QUEUE_KEY, *kept)

        logger.info(
            f"[RELEASE] ✅ Removed {removed_count} precise hold(s) "
            f"(biz={business_id}, user={user_id}, pet={pet_id}, product={product_id})"
        )

    except Exception as e:
        logger.exception(f"[RELEASE] ❌ Failed to release hold: {e}")


# ---------------------------------------------------------------------------
# CHECK LOGIC
# ---------------------------------------------------------------------------
def check_timeslot_queue(
    business_id: str | None = None, product_id: str | None = None
) -> list[dict]:
    """
    Returns all non-expired holds for a given business_id (and optionally product_id).
    Automatically removes expired holds from Redis.
    Each returned hold includes a 'ttl_remaining' field (seconds left until expiry).
    """
    r = get_redis_client()
    holds: list[dict] = []
    now = int(time.time())

    try:
        items = r.lrange(HOLD_QUEUE_KEY, 0, -1)
        valid_items = []
        expired = 0
        ttl_log_entries = []

        for raw in items:
            try:
                obj = json.loads(raw)
                timestamp = int(obj.get("timestamp", now))
                ttl = int(obj.get("expires_in", SOFT_HOLD_TTL))
                age = now - timestamp
                remaining = max(0, ttl - age)

                # --- Expired? Drop from queue ---
                if remaining <= 0:
                    expired += 1
                    logger.debug(f"[CHECK] ❌ Expired hold removed: {obj}")
                    continue

                # --- Filter by business_id / product_id ---
                if business_id and obj.get("business_id") != business_id:
                    continue
                if product_id and obj.get("product_id") != product_id:
                    continue

                # --- Add TTL field to the hold ---
                obj["ttl_remaining"] = remaining
                holds.append(obj)
                valid_items.append(json.dumps(obj))

                # --- Summarize for debug log ---
                ttl_log_entries.append(
                    f"{obj.get('time','?')} {remaining}s left (pet={obj.get('pet_id','?')})"
                )

            except Exception as e:
                logger.debug(f"[CHECK] ⚠️ Failed to parse Redis item: {e}")

        # --- Rewrite Redis queue (without expired) ---
        r.delete(HOLD_QUEUE_KEY)
        if valid_items:
            r.rpush(HOLD_QUEUE_KEY, *valid_items)

        # --- Summary log ---
        ttl_summary = ", ".join(ttl_log_entries[:8]) or "no active holds"
        logger.info(
            f"[CHECK] ✅ {len(holds)} active hold(s) for biz={business_id or 'ALL'} | "
            f"{expired} expired removed | TTLs: {ttl_summary}"
        )

    except Exception as e:
        logger.exception(f"[CHECK] ❌ Failed to check queue: {e}")

    return holds


def clear_user_holds_on_booking_confirmed(
    db: Session,
    business_id: str,
    user_id: str,
):
    """
    Remove ALL hold entries for the given user within a business.
    Called after bookings are successfully confirmed/submitted.
    """
    import json

    user_id = str(user_id)
    r = get_redis_client()

    logger.debug(
        f"[BOOKING CONFIRMED] Clearing all holds for biz={business_id}, user={user_id}"
    )

    try:
        items = r.lrange(HOLD_QUEUE_KEY, 0, -1)
        kept: list[str] = []
        removed_count = 0

        for i, raw in enumerate(items):
            try:
                obj = json.loads(raw)
                if (
                    obj.get("business_id") == business_id
                    and obj.get("user_id") == user_id
                ):
                    removed_count += 1
                    logger.debug(f"[BOOKING CONFIRMED] 🟢 Removing hold: {obj}")
                else:
                    kept.append(raw)
            except Exception as e:
                logger.warning(f"[BOOKING CONFIRMED] Could not parse item #{i}: {e}")
                kept.append(raw)

        # Replace queue with remaining holds
        r.delete(HOLD_QUEUE_KEY)
        if kept:
            r.rpush(HOLD_QUEUE_KEY, *kept)

        logger.info(
            f"[BOOKING CONFIRMED] ✅ Cleared {removed_count} hold(s) "
            f"for biz={business_id}, user={user_id}"
        )

    except Exception as e:
        logger.exception(f"[BOOKING CONFIRMED] ❌ Failed to clear holds: {e}")
