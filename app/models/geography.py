from sqlalchemy import Column, String, Integer
from sqlalchemy.ext.declarative import declarative_base

Base_Geography = declarative_base()

class AnalyticsData(Base_Geography):
    __tablename__ = "regent"
    idregent = Column(Integer, primary_key=True)
    name = Column(String(255))
    area = Column(String(255))
    capital = Column(String(255))