from typing import Any, Dict

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from app.reports.generator import generate_audit_report


router = APIRouter(
    prefix="/api/reports",
    tags=["Reports"],
)


class ReportRequest(BaseModel):
    audit_result: Dict[str, Any] = Field(default_factory=dict)


@router.post("/generate")
def generate_report(request: ReportRequest):
    """
    Generate a PDF report from a completed audit result.
    """

    if not request.audit_result:
        raise HTTPException(
            status_code=400,
            detail="Audit result is required.",
        )

    try:
        report_path = generate_audit_report(request.audit_result)

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to generate PDF report: {exc}",
        ) from exc

    return FileResponse(
        path=str(report_path),
        media_type="application/pdf",
        filename=report_path.name,
    )