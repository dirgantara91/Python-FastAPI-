from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker,Session

SQLALCHEMY_DATABASE_URL_SECURITY = "mysql+pymysql://root:Kepandean%4095@localhost/security"
engine_security = create_engine(SQLALCHEMY_DATABASE_URL_SECURITY)
Base_Security = declarative_base()

SQLALCHEMY_DATABASE_URL_GEOGRAPHY = "mysql+pymysql://root:Kepandean%4095@localhost/geography"
engine_geography = create_engine(SQLALCHEMY_DATABASE_URL_GEOGRAPHY)
Base_Geography = declarative_base()

SessionLocal_Security = sessionmaker(autocommit=False, autoflush=False, bind=engine_security)
SessionLocal_Geography = sessionmaker(autocommit=False, autoflush=False, bind=engine_geography)

def get_db1():
    db = SessionLocal_Security()
    try:
        yield db
    finally:
        db.close()

def get_db2():
    db = SessionLocal_Geography()
    try:
        yield db
    finally:
        db.close()