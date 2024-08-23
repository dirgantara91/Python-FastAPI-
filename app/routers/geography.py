from fastapi import APIRouter, Depends, HTTPException, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pytest import Session 
from app.db import get_db2
from app.models.geography import AnalyticsData
from app.schemas.geography import RegentsOut
from app.utils.auth import verify_token
from pydantic import BaseModel
from typing import List
from fastapi import Depends

security = HTTPBearer()

geography_router = APIRouter(prefix="/geography", tags=["geography"], redirect_slashes=False)

class Regent(BaseModel):
    idregent: int
    name: str
    area: str
    capital: str

@geography_router.get("/regents/", response_model=List[Regent], summary="Retrieve list of regents", response_description="List of regents")
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
    except TypeError as e:
        raise HTTPException(status_code=401, detail=str(e))
    regents = db.query(AnalyticsData).all()
    return [{"idregent": regent.idregent, "name": regent.name, "area": regent.area, "capital": regent.capital} for regent in regents]