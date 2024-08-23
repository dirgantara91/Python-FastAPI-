from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer, HTTPBearer, HTTPAuthorizationCredentials
from app.db import SessionLocal_Security, get_db1
from app.models.security import User, Token
from app.schemas.security import UserInDB, UserOut, TokenOut
from app.utils.auth import verify_token
from fastapi import Depends
#from app.utils.token import generate_token
import jwt
from bcrypt import gensalt, hashpw, checkpw
from datetime import datetime, timedelta
import pytz
import threading
import re

security_router = APIRouter(prefix="/security", tags=["security"], redirect_slashes=False)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def hash_password(password: str) -> str:
    salt = gensalt()
    hashed_password = hashpw(password.encode(), salt)
    return hashed_password.decode()

def check_password(password: str, hashed_password: str) -> bool:
    return checkpw(password.encode(), hashed_password.encode())



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


# Define a function to validate the password
def validate_password(password: str):
    if not re.match(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,12}$", password):
        raise HTTPException(status_code=400, detail="Password must have at least 1 capital letter, 1 small letter, 1 numeric and 1 symbol, and be between 8 and 12 characters long.")

# Update the create_user function to include password validation
@security_router.post("/users/")
async def create_user(userid: str, username: str, email: str, password: str, db: SessionLocal_Security = Depends(get_db1)): # type: ignore
    existing_user = None
    try:
        existing_user = db.query(User).filter((User.userid == userid) | (User.email == email)).first()
        if existing_user:
            print(f"User ID or email already exists!")
            raise HTTPException(status_code=400, detail="User or email already exists!")
        
        # Validate the password
        validate_password(password)
        encrypted_password = hash_password(password)
        
        user = User(userid=userid, username=username, email=email, password_hash=encrypted_password)
        db.add(user)
        db.commit()
        return {"message": "User created successfully"}
    except Exception as e:
        if existing_user:
            print(f"An error occurred: {e}. User or email already exists!")
            raise HTTPException(status_code=400, detail="User or email already exists!")
        elif "Password must have at least 1 capital letter, 1 small letter, 1 numeric and 1 symbol, and be between 8 and 12 characters long." in str(e):
            print(f"An error occurred: {e}")
            raise HTTPException(status_code=400, detail="Password must have at least 1 capital letter, 1 small letter, 1 numeric and 1 symbol, and be between 8 and 12 characters long.")
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
    # ...