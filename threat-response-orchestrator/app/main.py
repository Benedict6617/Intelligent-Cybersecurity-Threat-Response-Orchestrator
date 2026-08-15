"""
Intelligent Cybersecurity Threat Response Orchestrator
--------------------------------------------------------
FastAPI application entrypoint. Wires together ingestion, correlation,
playbook automation, threat intel, and compliance reporting into a
single SOAR API surface, plus a lightweight static analyst dashboard.

Run locally:
    uvicorn app.main:app --reload

Then visit:
    http://localhost:8000/docs      (interactive API docs)
    http://localhost:8000/dashboard (analyst dashboard UI)
"""
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from app.config import get_settings
from app.database import init_db
from app.api.routes import ingestion, incidents, playbooks, threat_intel, compliance, dashboard
from app.utils.logger import get_logger

settings = get_settings()
logger = get_logger("main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting %s [%s]", settings.APP_NAME, settings.APP_ENV)
    init_db()
    yield
    logger.info("Shutting down %s", settings.APP_NAME)


app = FastAPI(
    title=settings.APP_NAME,
    description=(
        "A SOAR platform that ingests SIEM/EDR/firewall/cloud telemetry, correlates "
        "threats against the MITRE ATT&CK framework, suppresses false positives, "
        "coordinates ITSM ticketing, manages incident escalation, executes automated "
        "containment playbooks, and produces SOC 2 / ISO 27001 audit evidence."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten to your analyst UI origin(s) in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(ingestion.router, prefix=settings.API_V1_PREFIX)
app.include_router(incidents.router, prefix=settings.API_V1_PREFIX)
app.include_router(playbooks.router, prefix=settings.API_V1_PREFIX)
app.include_router(threat_intel.router, prefix=settings.API_V1_PREFIX)
app.include_router(compliance.router, prefix=settings.API_V1_PREFIX)
app.include_router(dashboard.router, prefix=settings.API_V1_PREFIX)

app.mount("/dashboard", StaticFiles(directory="dashboard", html=True), name="dashboard")


@app.get("/", tags=["health"])
def root():
    return {
        "service": settings.APP_NAME,
        "status": "operational",
        "environment": settings.APP_ENV,
        "docs": "/docs",
        "dashboard": "/dashboard",
    }


@app.get("/healthz", tags=["health"])
def healthz():
    return {"status": "ok"}
