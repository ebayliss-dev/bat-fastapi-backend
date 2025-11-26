from sqlalchemy import TIMESTAMP, BigInteger, Boolean, Column, Integer, Numeric, String, DateTime, Text, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
import uuid

Base = declarative_base()

class Beer(Base):
    __tablename__ = "beers"
    __table_args__ = {"schema": "public"}

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, unique=True)

    # pub_id stored as a normal UUID column (NO FK constraint)
    pub_id = Column(UUID(as_uuid=True), nullable=False)

    pumpclip = Column(Text)
    pngpclip = Column(Text)
    brewery = Column(Text, nullable=False)
    productname = Column(Text, nullable=False)
    abv = Column(Numeric(4, 2))
    tastingnotes = Column(Text)
    price = Column(Numeric(6, 2))
    tag = Column(Text)
    ctype = Column(Text)
    style = Column(Text)
    stylecode = Column(Text)
    colorfrom = Column(Text)
    colorto = Column(Text)
    shortstyledesc = Column(Text)
    status = Column(Text)
    allergens = Column(Text)
    allergens_text = Column(Text)

    sold_out = Column(Boolean, nullable=False, default=False)
    new = Column(Boolean, nullable=False, default=False)

    created_at = Column(TIMESTAMP(timezone=False), server_default=func.now())


class BeerVote(Base):
    __tablename__ = "beervotes"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    beer_id  = Column(UUID(as_uuid=True), nullable=False)
    pub_id   = Column(UUID(as_uuid=True), nullable=False)
    user_id  = Column(UUID(as_uuid=True), nullable=False)
    event_id = Column(UUID(as_uuid=True), nullable=True)

    rating = Column(Integer, nullable=False)
    review = Column(Text, nullable=True)

    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())
