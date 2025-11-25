from sqlalchemy import TIMESTAMP, BigInteger, Boolean, Column, Integer, String, DateTime, Text, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
import uuid

Base = declarative_base()



class Log(Base):
    __tablename__ = "logs"
    uuid = Column(UUID(as_uuid=True), primary_key=True)
    body = Column(String)
    added = Column(TIMESTAMP)