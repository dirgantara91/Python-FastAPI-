import jwt
from datetime import datetime,timedelta

def generate_token(userid: str) -> str:
 async def generate_token_coro(userid: str):
        payload = {"userid": userid, "exp": datetime.utcnow() + timedelta(minutes=180),"last_activity": datetime.utcnow().isoformat()}
        token = jwt.encode(payload, "secret", algorithm="HS256")
        return token  # Return the token as a string       # ...