from pydantic import BaseModel

class RegentsOut(BaseModel):
    idregent: int
    name: str
    area: str
    capital: str