from fastapi import FastAPI, Depends, HTTPException, Request
from typing import List
import logging
from contextlib import asynccontextmanager
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from fastapi.middleware.cors import CORSMiddleware

from core.models import ScanRequest, ScanResponse, ScanResult, Finding, ScanSummary
from core.orchestrator import scan_manager
from core.security import verify_api_key, validate_target_url
from config import settings

# Rate Limiter Setup
limiter = Limiter(key_func=get_remote_address)

# Configure Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Sync history from adapters
    try:
        await scan_manager.sync_from_adapters()
    except Exception as e:
        logging.error(f"Startup sync failed: {e}")
    
    yield
    # Shutdown: Clean up?

app = FastAPI(title="DAST Orchestrator", lifespan=lifespan)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins (adjust for production)
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

from routers.mobsf import router as mobsf_router
from routers.nmap import router as nmap_router
from routers.garak import router as garak_router
from routers.dashboard import router as dashboard_router
from routers.acunetix import router as acunetix_router
from routers.logs import router as logs_router
from routers.admin import router as admin_router

app.include_router(acunetix_router, prefix="/api/v1")
app.include_router(mobsf_router, prefix="/api/v1")
app.include_router(nmap_router, prefix="/api/v1")
app.include_router(garak_router, prefix="/api/v1")
app.include_router(dashboard_router, prefix="/api/v1")
app.include_router(logs_router, prefix="/api/v1")
app.include_router(admin_router, prefix="/api/v1")

@app.get("/health")
async def health_check():
    return {"status": "ok"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8060)
