from pydantic import BaseModel

class UserInDB(BaseModel):
    userid: str
    password_hash: str

class UserOut(BaseModel):
    userid: str

class TokenOut(BaseModel):
    access_token: str
    token_type: str