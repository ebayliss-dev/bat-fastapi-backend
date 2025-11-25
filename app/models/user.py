from sqlalchemy import BigInteger, Boolean, Column, Integer, String, DateTime, Text, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
import uuid

Base = declarative_base()



class User(Base):
    __tablename__ = "accounts"
    __table_args__ = {"schema": "public"}

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)

    firstname = Column(String(64), nullable=False)
    surname = Column(String(64), nullable=False)
    number = Column(String(64), nullable=False, unique=True, index=True)

    password = Column(String(256), nullable=True)

    created_on = Column(DateTime(timezone=False), server_default=func.now(), nullable=True)
    last_login = Column(DateTime(timezone=False), nullable=True)

    user_name = Column(String(64), nullable=False)

    credits = Column(BigInteger, nullable=True)
    total_credits = Column(BigInteger, nullable=True)

    bonus = Column(Boolean, nullable=True)

    image = Column(String, nullable=True)
    push_id = Column(String, nullable=True)


    # Properties for compatibility with the API
    @property
    def is_active(self) -> bool:
        """Always return True since we don't have this column"""
        return True

    @property
    def is_superuser(self) -> bool:
        """Default to False for now"""
        return False

    @property
    def username(self) -> str:
        """Username is the same as email"""
        return self.email
