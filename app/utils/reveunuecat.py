from datetime import datetime, timezone
import os

from fastapi import HTTPException, requests
from sqlalchemy import text
import stripe

from app.models.business import BusinessAccount
from app.models.client import Client

REVENUECAT_SECRET_KEY = os.getenv(
    "REVENUECAT_SECRET_KEY", "sk_VUHpIdCToshElilznToGSsSRLCyQb"
)
REVENUECAT_ENTITLEMENT = os.getenv("REVENUECAT_ENTITLEMENT", "pro")  # change if needed

stripe.api_key = os.getenv(
    "STRIPE_API_KEY",
    "k_live_51LXREQIdMMgqrK9PaQW63uVGwCj7HYkLO9T3w2Tvu5z3QWgxxBB0VPZEyzbm2H30Ktz8QDbwzk8u3GfNqFafIBUv008KUq6TZL",
)


def is_user_subscribed(db, app_user_id: str) -> tuple[bool, str]:
    rc = revenuecat_is_active(app_user_id)
    stp = stripe_subscription_is_active(db, app_user_id)
    from sqlalchemy import text

    message = "no subscription"

    # 1) Look up the business_id for this user
    biz = (
        db.execute(
            text(
                """
            SELECT business_id::text AS id
            FROM prod.business_accounts
            WHERE user_id = :user_id
            LIMIT 1
        """
            ),
            {"user_id": str(app_user_id)},
        )
        .mappings()
        .first()
    )
    if not biz:
        clients = 0
        pets = 0

    else:
        # 2) Count clients for that business_id
        row = db.execute(
            text(
                """
                SELECT COUNT(*) AS total_clients
                FROM prod.clients
                WHERE business_id = :biz_id
            """
            ),
            {"biz_id": biz["id"]},
        ).first()
        clients = row.total_clients if row else 0

        row = db.execute(
            text(
                """
                SELECT COUNT(*) AS total_pets
                FROM prod.pets
                WHERE business_id = :biz_id
            """
            ),
            {"biz_id": biz["id"]},
        ).first()
        pets = row.total_pets if row else 0

        if pets > 200 or clients > 200:
            message = 1
        else:
            message = 0
        rc = True
    return (rc or stp, message)


def revenuecat_is_active(app_user_id: str) -> bool:
    """
    Returns True if the user has an active RevenueCat entitlement.
    """
    url = f"https://api.revenuecat.com/v1/subscribers/{app_user_id}"
    headers = {"Authorization": f"Bearer {REVENUECAT_SECRET_KEY}"}

    try:
        resp = requests.get(url, headers=headers, timeout=12)
    except Exception:
        return False

    if resp.status_code != 200:
        return False

    data = resp.json()
    req_date = data.get("request_date")  # ISO8601 string
    entitlements = (data.get("subscriber") or {}).get("entitlements") or {}

    # If a specific entitlement is configured, check that first
    if REVENUECAT_ENTITLEMENT in entitlements:
        e = entitlements[REVENUECAT_ENTITLEMENT]
        exp = e.get("expires_date")  # ISO8601 or None for lifetime
        return (exp is None) or (req_date and exp > req_date)

    # Otherwise, consider ANY active entitlement valid
    for e in entitlements.values():
        exp = e.get("expires_date")
        if (exp is None) or (req_date and exp > req_date):
            return True

    return False


def valid_request(db, app_user_id: str):
    subscribed, msg = is_user_subscribed(db, str(app_user_id))
    if not subscribed:
        raise HTTPException(status_code=402, detail="No Subscription")
    if msg == 1:
        raise HTTPException(status_code=402, detail=msg)


def stripe_subscription_is_active(db, app_user_id: str | None) -> bool:
    """
    Returns True if the Stripe subscription is active or trialing.
    """
    business_account = db.query(BusinessAccount).filter_by(user_id=app_user_id).first()
    if not business_account:
        client = db.query(Client).filter_by(id=app_user_id).first()
        if client:
            business_account = (
                db.query(BusinessAccount)
                .filter_by(business_id=client.business_id)
                .first()
            )
            if not client:
                raise HTTPException(
                    status_code=404, detail="Business account not found"
                )
    subscription = db.execute(
        text("SELECT * FROM prod.subscriptions WHERE business_id = :business_id"),
        {"business_id": business_account.business_id},
    ).fetchone()
    if not subscription:
        return {
            "has_subscription": False,
            "status": "No Stripe",
            "active": False,
            "message": "No subscription found for this business",
        }

    subscription_id = subscription.subscription_id
    if not subscription_id:
        return False

    try:
        sub = stripe.Subscription.retrieve(subscription_id)
    except Exception:
        return False

    if subscription.status in {"trial"}:
        current_period_end = subscription.end_of_cycle
        if current_period_end:
            # Parse string like "2025-09-30 20:23:24.753246"
            end_dt = datetime.strptime(current_period_end, "%Y-%m-%d %H:%M:%S.%f")
            # Make it timezone-aware (UTC)
            end_dt = end_dt.replace(tzinfo=timezone.utc)

            now = datetime.now(timezone.utc)

            # Still active if now is before end of cycle
            return now < end_dt
        return True
    if sub.status in {"active"}:
        return True
    return False
