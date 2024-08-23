from fastapi import FastAPI
from fastapi_versioning import VersionedFastAPI
from app.routers import security_router, geography_router

app = FastAPI(
    title="My Awesome API",
    description="This is a description of my API",
    version="1.0.0"
)

app.include_router(security_router)
app.include_router(geography_router)

versioned_app = VersionedFastAPI(app, version_format="{major}.{minor}", prefix_format="/v{major}", version="1.0")