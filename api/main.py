"""
api/main.py

FastAPI application entry point.

Run locally:
    uvicorn api.main:app --reload --port 8000

Docs available at: http://localhost:8000/docs
"""

from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.routers import orgs

app = FastAPI(
    title       = "Firmable Sales Intelligence API",
    description = "Attack-surface-based prospect scoring for cybersecurity sales teams.",
    version     = "0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins  = ["*"],  # tighten for production
    allow_methods  = ["*"],
    allow_headers  = ["*"],
)

app.include_router(orgs.router)


@app.get("/health")
def health():
    return {"status": "ok"}
