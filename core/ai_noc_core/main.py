from __future__ import annotations
import os
from fastapi import FastAPI
from .ingest import router as ingest_router

app = FastAPI(title="AI-NOC Core", version="0.1.0")
app.include_router(ingest_router)

@app.get("/health")
def health():
    return {"ok": True}

def run():
    import uvicorn
    host = os.environ.get("HOST","0.0.0.0")
    port = int(os.environ.get("PORT","8080"))
    uvicorn.run("ai_noc_core.main:app", host=host, port=port, reload=False)

