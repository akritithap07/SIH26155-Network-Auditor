from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.analysis import router as analysis_router
from app.api.reports import router as reports_router
from app.api.training import router as training_router
from app.api.upload import router as upload_router


app = FastAPI(
    title="SIH26155 Network Security Compliance Engine",
    description=(
        "AI-assisted, vendor-agnostic network security "
        "configuration auditor"
    ),
    version="0.1.0",
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


app.include_router(upload_router)
app.include_router(analysis_router)
app.include_router(training_router)
app.include_router(reports_router)


@app.get("/health")
def health_check():
    return {
        "status": "ok",
        "service": "network-security-compliance-engine",
        "version": "0.1.0",
    }