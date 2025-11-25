from sqlalchemy import text
from sqlalchemy.orm import Session
from sqlalchemy import or_
from app.models.user import User
from app.password_utils import generate_password_hash, check_password_hash
from datetime import datetime
import uuid
from typing import Optional


def verify_password(plain_password, hashed_password):
    return check_password_hash(hashed_password, plain_password)


def verify_client_password(plain_password, hashed_password):
    if plain_password == hashed_password:
        return True
    else:
        return False


def get_password_hash(password):
    return generate_password_hash(password)


# User CRUD operations
def get_user(db: Session, user_id: uuid.UUID):
    return db.query(User).filter(User.id == user_id).first()




def get_user_by_number(db: Session, number: str):
    """Get user by number (which is also the username)"""
    return db.query(User).filter(User.number == number).first()



def get_users(db: Session, skip: int = 0, limit: int = 100):
    return db.query(User).offset(skip).limit(limit).all()

    # def create_user(db: Session, user: schemas.UserCreate):
    #     hashed_password = get_password_hash(user.password)
    #     db_user = User(
    #         email=user.email,
    #         firstname=user.firstname,
    #         surname=user.surname,
    #         password=hashed_password,
    #         # Removed is_active since it doesn't exist in the database
    #     )
    #     db.add(db_user)
    #     db.commit()
    #     db.refresh(db_user)
    return db_user


# def update_user(db: Session, user_id: uuid.UUID, user: schemas.UserUpdate):
#     db_user = db.query(User).filter(User.id == user_id).first()
#     if db_user:
#         update_data = user.dict(exclude_unset=True)
#         for field, value in update_data.items():
#             setattr(db_user, field, value)
#         db.commit()
#         db.refresh(db_user)
#     return db_user


def update_user_last_login(db: Session, user_id: uuid.UUID):
    """Update the last_login timestamp for a user"""
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


def authenticate_user(db: Session, email: str, password: str):
    """Authenticate user using email (which serves as username)"""
    user = get_user_by_email(db, email)
    if not user:
        return False
    if not verify_password(password, user.password):
        return False
    # Removed is_active check since column doesn't exist
    return user




def change_password(
    db: Session, user_id: uuid.UUID, current_password: str, new_password: str
):
    user = get_user(db, user_id)
    if not user:
        return None
    if not verify_password(current_password, user.password):
        return False
    user.password = get_password_hash(new_password)
    db.commit()
    db.refresh(user)
    return user


# # Business Account CRUD operations
# def get_business_account(db: Session, business_account_id: uuid.UUID):
#     return db.query(models.BusinessAccount).filter(models.BusinessAccount.id == business_account_id).first()


# def get_business_accounts_by_user(db: Session, user_id: uuid.UUID):
#     return db.query(models.BusinessAccount).filter(models.BusinessAccount.user_id == user_id).all()

