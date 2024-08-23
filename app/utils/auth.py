import jwt
from datetime import datetime,timedelta
from fastapi import HTTPException

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
        raise HTTPException(status_code=401, detail="Invalid token")    # ...