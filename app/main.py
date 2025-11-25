import os, certifi
os.environ["SSL_CERT_FILE"] = certifi.where()
import json
import logging
import os
import time
from fastapi import FastAPI, Depends, Response
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.orm import Session
from app.database import SessionLocal, engine, Base
from app.models.user import User
from uuid import UUID
from app.__version__ import __version__

from app.routes import auth, beers, dashboard, pubs
from fastapi.middleware.cors import CORSMiddleware
from apscheduler.schedulers.background import BackgroundScheduler



Base.metadata.create_all(bind=engine)

app = FastAPI(title="FastAPI with PostgreSQL")



# Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@app.get("/.well-known/assetlinks.json", include_in_schema=False)
async def assetlinks_json():
    payload = [
        {
            "relation": ["delegate_permission/common.handle_all_urls"],
            "target": {
                "namespace": "android_app",
                "package_name": "com.pawtul",
                "sha256_cert_fingerprints": [
                    "FA:C6:17:45:DC:09:03:78:6F:B9:ED:E6:2A:96:2B:39:9F:73:48:F0:BB:6F:89:9B:83:32:66:75:91:03:3B:9C"
                ]
            }
        }
    ]
    return JSONResponse(
        content=payload,
        media_type="application/json",
        headers={"Cache-Control": "public, max-age=86400"}  # optional cache
    )


START_TIME = time.time()
@app.get("/api/ping", include_in_schema=False)
def ping(db: Session = Depends(get_db)):
    """
    Liveness/Readiness probe.
    Returns 200 if the process is up AND DB connectivity works.
    Your Docker healthcheck uses curl -f, so any 2xx is "healthy".
    """
    try:
        # Simple DB round-trip
        db.execute(text("SELECT 1"))
        # Optional: db.commit() not required for read, but harmless
        return {
            "status": "ok",
            "uptime_seconds": int(time.time() - START_TIME),
            "service": "pawtul_api",
            "version": os.getenv("APP_VERSION", "v1"),
        }
    except Exception as e:
        print(e)
        # If DB is down or connection pool isn't ready, signal unhealthy
        return
@app.get("/.well-known/apple-app-site-association", include_in_schema=False)
async def apple_app_site_association():
    aasa = {
        "applinks": {
            "apps": [],
            "details": [
            {
                "appID": "26GVP6K645.com.pawtul",
                "paths": [
                "/api/v1/reports/print/*",
                "/api/v1/invoices/print/*",
                "/magic/password-reset/*",
                "/magic/*",
                ]
            }
            ]
        }
        }

    return Response(
        content=json.dumps(aasa),
        media_type="application/json"
    )


# Include routers
app.include_router(
    auth.router, prefix=f"/api/{__version__}/auth", tags=["authentication"]
)
app.include_router(
    dashboard.router, prefix=f"/api/{__version__}/dashboard", tags=["dashboard"]
)

app.include_router(
    pubs.router, prefix=f"/api/{__version__}/pubs", tags=["pubs"]
)

app.include_router(
    beers.router, prefix=f"/api/{__version__}/beers", tags=["beers"]
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "*"
    ],  # Or better: ["http://localhost:19006", "https://yourdomain.com"]
    allow_credentials=True,
    allow_methods=["*"],  # Or just ["POST", "GET"]
    allow_headers=["*"],
)


@app.get("/")
def read_root():
    return {"message": "Welcome to BAT API"}


@app.get("/health")
def health_check():
    return {"status": "healthy"}
