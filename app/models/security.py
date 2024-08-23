from sqlalchemy import Column, String, DateTime, ForeignKey, Integer
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship

Base_Security = declarative_base()

class User(Base_Security):
    __tablename__ = "ms_user"
    userid = Column(String(15), primary_key=True)
    username = Column(String(255))
    email = Column(String(255), unique=True)
    password_hash = Column(String(255))

    tokens = relationship("Token", backref="user")

class Token(Base_Security):
    __tablename__ = "ms_token"
    token = Column(String(255), primary_key=True)
    userid = Column(String(15), ForeignKey("ms_user.userid"), nullable=False)
    expires_at = Column(DateTime, nullable=False)