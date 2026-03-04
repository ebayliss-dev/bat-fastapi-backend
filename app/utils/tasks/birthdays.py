import datetime
from typing import Dict, List, Optional
import uuid
from requests import Session
from sqlalchemy import text
from app.database import SessionLocal
from app.models.notifications import Notification
from app.routes.notifications import send_push_notification
from app.utils.scheduler import enqueue_notification


def birthdays(db: Optional[Session] = None) -> List[Dict]:
    """
    Return pets whose birthday is today, with client name and current age (years).
    """
    created_session = False
    if db is None:
        db = SessionLocal()
        created_session = True

    try:
        rows = (
            db.execute(
                text(
                    """
            SELECT
              p.id::text AS pet_id,
              p.name AS pet_name,
              p.business_id,
              c.firstname,
              c.lastname,
              (c.firstname || ' ' || c.lastname) AS client_name,
              EXTRACT(YEAR FROM AGE(CURRENT_DATE, TO_DATE(p.dob, 'YYYY-MM-DD')))::int AS age_years
            FROM prod.pets p
            LEFT JOIN prod.clients c
              ON c.id = p.client_id
            WHERE
              -- ensure dob looks like YYYY-MM-DD before casting
              p.dob ~ '^\d{4}-\d{2}-\d{2}$'
              AND TO_CHAR(CURRENT_DATE, 'MM-DD') = TO_CHAR(TO_DATE(p.dob, 'YYYY-MM-DD'), 'MM-DD');
        """
                )
            )
            .mappings()
            .all()
        )

        for birthday in rows:
            body = f"""It's {birthday.pet_name}'s birthday, they are {birthday.age_years} today, let's celebrate"""

            # enqueue into Redis
            enqueue_notification(
                "birthdays",
                {
                    "pet_id": str(birthday.pet_id),
                    "pet_name": str(birthday.pet_name),
                    "client_name": birthday.client_name,
                    "age_years": birthday.age_years,
                    "business_id": str(birthday.business_id),
                    "message": body,
                },
            )

    finally:
        if created_session:
            db.close()
