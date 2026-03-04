from sqlalchemy.orm import Session
from app.models.user import User
from datetime import datetime
import uuid


# ---------------------------------------------------------
# User CRUD (Passwordless / Magic Link Based)
# ---------------------------------------------------------

def get_user(db: Session, user_id: uuid.UUID):
    return db.query(User).filter(User.id == user_id).first()


def get_user_by_mobile(db: Session, mobile: str):
    """Mobile is now the unique login identifier"""
    return db.query(User).filter(User.number == mobile).first()


def get_users(db: Session, skip: int = 0, limit: int = 100):
    return db.query(User).offset(skip).limit(limit).all()


def create_user(db: Session, mobile: str):
    """Create user without password"""
    db_user = User(
        id=uuid.uuid4(),
        number=mobile,
        last_login=None,
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user


def update_user_last_login(db: Session, user_id: uuid.UUID):
    db_user = db.query(User).filter(User.id == user_id).first()
    if db_user:
        db_user.last_login = datetime.utcnow()
        db.commit()
        db.refresh(db_user)
    return db_user


def delete_user(db: Session, user_id: uuid.UUID):
    db_user = db.query(User).filter(User.id == user_id).first()
    if db_user:
        db.delete(db_user)
        db.commit()
    return db_user