from pydantic import BaseModel
from sqlalchemy import TIMESTAMP, BigInteger, Boolean, Column, Integer, String, DateTime, Text, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
import uuid

Base = declarative_base()

class Pub(Base):
    __tablename__ = "pubs"
    __table_args__ = {"schema": "public"}

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, unique=True)

    token = Column(String(128), nullable=False, unique=True)

    name = Column(String(128), nullable=False)
    description = Column(String(10240), nullable=False)
    phone = Column(String(128), nullable=False)
    landlord = Column(String(128), nullable=False)
    manager = Column(String(128), nullable=False)
    social1 = Column(String(128), nullable=False)
    social2 = Column(String(128), nullable=False)
    web = Column(String(128), nullable=False)
    logo = Column(String(1024), nullable=False)
    photo1 = Column(String(1024), nullable=False)
    photo2 = Column(String(1024), nullable=False)
    longitude = Column(String(1024), nullable=False)
    latitude = Column(String(1024), nullable=False)
    opening_times = Column(String(1024), nullable=False)
    beer_board = Column(String(1024), nullable=False)

    # REQUIRED for RealAleFinder sync
    token = Column(String(128), nullable=False, unique=True)