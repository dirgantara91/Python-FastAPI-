from fastapi import FastAPI, Depends, HTTPException,Security,APIRouter
from fastapi.security import OAuth2PasswordBearer, HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse
from fastapi.requests import Request
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, String, DateTime, ForeignKey,Integer
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship,Session
from bcrypt import gensalt, hashpw, checkpw
from fastapi.openapi.utils import get_openapi
from fastapi_versioning import VersionedFastAPI
import jwt
from jwt import encode
import uuid
from datetime import datetime
import pytz
from datetime import timedelta
import threading
from fastapi_versioning import versioned_api_route,VersionedFastAPI

app = FastAPI(
    title="My Awesome API",
    description="This is a description of my API",
    version="1.0.0"
)

# Database 1 connection
SQLALCHEMY_DATABASE_URL_SECURITY = "mysql+pymysql://root:Kepandean%4095@localhost/security"
engine_security = create_engine(SQLALCHEMY_DATABASE_URL_SECURITY)
Base_Security = declarative_base()

# Define models for Database 1
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

# Create tables for Database 1
Base_Security.metadata.create_all(engine_security)

# Database 2 connection
SQLALCHEMY_DATABASE_URL_GEOGRAPHY = "mysql+pymysql://root:Kepandean%4095@localhost/geography"
engine_geography = create_engine(SQLALCHEMY_DATABASE_URL_GEOGRAPHY)
Base_Geography = declarative_base()

# Define models for Database 2
class AnalyticsData(Base_Geography):
    __tablename__ = "regent"
    idregent = Column(Integer, primary_key=True)
    name = Column(String(255))
    area = Column(String(255))
    capital = Column(String(255))
    

# Create tables for Database 2
Base_Geography.metadata.create_all(engine_geography)

# Create a session maker for Database 1 (security)
SessionLocal_Security = sessionmaker(autocommit=False, autoflush=False, bind=engine_security)

# Create a session maker for Database 2 (geography)
SessionLocal_Geography = sessionmaker(autocommit=False, autoflush=False, bind=engine_geography)

# Dependency to get a database session for Database 1
def get_db1():
    db = SessionLocal_Security()
    try:
        yield db
    finally:
        db.close()

# Dependency to get a database session for Database 2
def get_db2():
    db = SessionLocal_Geography()
    try:
        yield db
    finally:
        db.close()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token",scopes={"regents:read": "Read regents"})
security = HTTPBearer()



# Define Pydantic models
class UserInDB(BaseModel):
    userid: str
    password_hash: str

class UserOut(BaseModel):
    userid: str

class TokenOut(BaseModel):
    access_token: str
    token_type: str

# Define functions
def hash_password(password: str) -> str:
    salt = gensalt()
    hashed_password = hashpw(password.encode(), salt)
    return hashed_password.decode()

def check_password(password: str, hashed_password: str) -> bool:
    return checkpw(password.encode(), hashed_password.encode())

#def generate_token(userid: str) -> str:
    payload = {"userid": userid, "exp": datetime.utcnow() + timedelta(minutes=30)}
    token = jwt.encode(payload, "secret", algorithm="HS256")
    return token.decode("utf-8")  # Decode the token to a string

#def verify_token(token: str) -> str:
    try:
        payload = jwt.decode(token, "secret", algorithms=["HS256"])
        return payload["userid"]
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.PyJWTError:  
        raise HTTPException(status_code=401, detail="Invalid token")

def verify_token(token: str) -> str:
    try:
        payload = jwt.decode(token, "secret", algorithms=["HS256"])
        userid = payload["userid"]
        last_activity = payload.get("last_activity")
        
        if last_activity:
            last_activity_date = datetime.fromisoformat(last_activity)
            if datetime.utcnow() - last_activity_date > timedelta(minutes=10):
                raise jwt.ExpiredSignatureError("Token has expired due to inactivity")
        
        return userid
    
    except jwt.ExpiredSignatureError as e:
        if str(e) == "Token has expired due to inactivity":
            raise HTTPException(status_code=401, detail="Token has expired due to inactivity")
        else:
            raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

 # Create routers for each group of endpoints
security_router = APIRouter(prefix="/security", tags=["security"],redirect_slashes=False)
geography_router = APIRouter(prefix="/geography", tags=["geography"],redirect_slashes=False)

  

@security_router.post("/token")
async def login_for_access_token(userid: str, password: str, db=Depends(get_db1)):
    user = db.query(User).filter_by(userid=userid).first()
    if not user:
        user = db.query(User).filter_by(email=userid).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
    if not check_password(password, user.password_hash):
        raise HTTPException(status_code=401, detail="Incorrect password")

    # Delete existing token for the user
    db.query(Token).filter_by(userid=userid).delete()
    db.commit()

    # Create a coroutine to generate the token
    async def generate_token_coro(userid: str):
        payload = {"userid": userid, "exp": datetime.utcnow() + timedelta(minutes=180),"last_activity": datetime.utcnow().isoformat()}
        token = jwt.encode(payload, "secret", algorithm="HS256")
        return token  # Return the token as a string    
    
    # Run the coroutine to generate the token
    token = await generate_token_coro(userid)

    # Create a thread to save the token to the database
    def save_token_to_db(token, userid):
        try:
            db_thread = SessionLocal()
            token_obj = Token(token=token, userid=userid, expires_at=datetime.utcnow().replace(tzinfo=pytz.UTC) + timedelta(minutes=30))
            db_thread.add(token_obj)
            db_thread.commit()
            db_thread.close()  # Close the session
        except Exception as e:
            print(f"Error saving token to database: {e}")

    thread = threading.Thread(target=save_token_to_db, args=(token, userid))
    thread.start()

    return TokenOut(access_token=token, token_type="bearer")

@security_router.post("/users/")
async def create_user(userid: str, username: str, email: str, password: str, db: SessionLocal_Security = Depends(get_db1)):
    existing_user = None
    try:
        existing_user = db.query(User).filter((User.userid == userid) | (User.email == email)).first()
        if existing_user:
            print(f"User or email already exists!")
            raise HTTPException(status_code=400, detail="User or email already exists!")
        encrypted_password = hash_password(password)
        
        user = User(userid=userid, username=username, email=email, password_hash=encrypted_password)
        db.add(user)
        db.commit()
        return {"message": "User created successfully"}
    except Exception as e:
        if existing_user:
            print(f"An error occurred: {e}. User or email already exists!")
            raise HTTPException(status_code=400, detail="User or email already exists!")
        else:
            print(f"An error occurred: {e}")
            raise HTTPException(status_code=500, detail="An error occurred")

@security_router.get("/users/me")
async def read_users_me(token: str = Depends(oauth2_scheme), db: SessionLocal_Security = Depends(get_db1)):
    userid = verify_token(token)
    user = db.query(User).filter_by(userid=userid).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return UserOut(userid=user.userid)

@security_router.post("/generate-token")
async def generate_token(db: SessionLocal_Security = Depends(get_db1)):
    userid = 'admin'
    user = db.query(User).filter_by(userid=userid).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Delete existing token for the user
    db.query(Token).filter_by(userid=userid).delete()
    db.commit()

    # Create a coroutine to generate the token
    async def generate_token_coro(userid: str):
        payload = {"userid": userid, "exp": datetime.utcnow() + timedelta(minutes=180),"last_activity": datetime.utcnow().isoformat()}
        token = jwt.encode(payload, "secret", algorithm="HS256")
        return token  # Return the token as a string

    # Run the coroutine to generate the token
    token = await generate_token_coro(userid)
    user.tokens = [Token(token=token, userid=userid, expires_at=datetime.utcnow().replace(tzinfo=pytz.UTC) + timedelta(minutes=30))]
    db.add(user)
    db.commit()
    return TokenOut(access_token=token, token_type="bearer")



@geography_router.get("/regents/", summary="Retrieve list of regents", response_description="List of regents")
async def read_regents(credentials: HTTPAuthorizationCredentials = Security(security), db: Session = Depends(get_db2)):
    """
    Get a list of regents.
    -------------------------

    This endpoint retrieves a list of regents.
    
    Args:
    - credentials (HTTPAuthorizationCredentials): The authentication credentials.
    - db (Session): The database session.

    Returns:
    - A list of regents.
    """

    token = credentials.credentials
    try:
        userid = verify_token(token)
    except Exception as e:
        raise HTTPException(status_code=401, detail=str(e))
    regents = db.query(AnalyticsData).all()
    return [{"idregent": regent.idregent, "name": regent.name, "area": regent.area, "capital": regent.capital} for regent in regents]

app.router.redirect_slashes = False #Optional
# Add routers to the main app
app.include_router(security_router)
app.include_router(geography_router)
versioned_app = VersionedFastAPI(app, version_format="{major}.{minor}", prefix_format="/v{major}", version="1.0")
