from typing import Any, Dict

from fastapi import APIRouter, File, HTTPException, UploadFile

from app.compliance.engine import run_compliance
from app.parsers.cisco_parser import CiscoIOSParser
from app.parsers.detector import detect_vendor
from app.parsers.pfsense_parser import PfSenseParser


router = APIRouter(
    prefix="/api",
    tags=["Analysis"],
)


MAX_FILE_SIZE = 2 * 1024 * 1024


def _model_to_dict(model: Any) -> Dict[str, Any]:
    if hasattr(model, "model_dump"):
        return model.model_dump()

    return model.dict()


async def _read_configuration(
    file: UploadFile,
) -> tuple[str, bytes]:
    if not file.filename:
        raise HTTPException(
            status_code=400,
            detail="No filename provided.",
        )

    content = await file.read()

    if not content:
        raise HTTPException(
            status_code=400,
            detail="Uploaded configuration file is empty.",
        )

    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=413,
            detail=(
                "Configuration file is too large. "
                "Maximum size is 2 MB."
            ),
        )

    try:
        config_text = content.decode("utf-8-sig")

    except UnicodeDecodeError as exc:
        raise HTTPException(
            status_code=400,
            detail="Configuration file must be UTF-8 text.",
        ) from exc

    return config_text, content


def _create_parser(vendor: str):
    if vendor == "cisco_ios":
        return CiscoIOSParser()

    if vendor == "pfsense":
        return PfSenseParser()

    return None


@router.post("/normalize")
async def normalize_configuration(
    file: UploadFile = File(...),
):
    """
    Parse a supported configuration and convert it into
    the vendor-neutral normalization schema.
    """

    config_text, content = await _read_configuration(file)

    detection = detect_vendor(config_text)

    if detection["vendor"] == "unknown":
        return {
            "filename": file.filename,
            "status": detection["status"],
            "detection": detection,
            "normalized": None,
            "message": (
                "Vendor could not be identified. "
                "Configuration was not parsed by a "
                "vendor-specific parser."
            ),
        }

    parser = _create_parser(
        str(detection["vendor"])
    )

    if parser is None:
        raise HTTPException(
            status_code=422,
            detail=(
                "No parser is available for the "
                "detected vendor."
            ),
        )

    try:
        normalized = parser.parse(config_text)

    except (TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=422,
            detail=str(exc),
        ) from exc

    return {
        "filename": file.filename,
        "status": "normalized",
        "size_bytes": len(content),
        "line_count": len(
            config_text.splitlines()
        ),
        "detection": detection,
        "normalized": _model_to_dict(
            normalized
        ),
    }


@router.post("/audit")
async def audit_configuration(
    file: UploadFile = File(...),
):
    """
    Perform a complete configuration audit.

    Pipeline:
        upload
        -> vendor detection
        -> vendor-specific parsing
        -> normalization
        -> deterministic compliance evaluation

    Unknown vendors are never guessed.
    """

    config_text, content = await _read_configuration(file)

    detection = detect_vendor(config_text)

    vendor = str(detection["vendor"])

    if vendor == "unknown":
        return {
            "filename": file.filename,
            "status": "unknown_vendor",
            "size_bytes": len(content),
            "line_count": len(
                config_text.splitlines()
            ),
            "detection": detection,
            "normalized": None,
            "compliance": None,
            "message": (
                "The vendor could not be identified. "
                "No vendor-specific compliance assessment "
                "was performed."
            ),
        }

    parser = _create_parser(vendor)

    if parser is None:
        raise HTTPException(
            status_code=422,
            detail=(
                "No parser is available for "
                f"vendor '{vendor}'."
            ),
        )

    try:
        normalized = parser.parse(
            config_text
        )

        compliance = run_compliance(
            normalized
        )

    except (TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=422,
            detail=str(exc),
        ) from exc

    return {
        "filename": file.filename,
        "status": "audit_complete",
        "size_bytes": len(content),
        "line_count": len(
            config_text.splitlines()
        ),
        "detection": detection,
        "normalized": _model_to_dict(
            normalized
        ),
        "compliance": compliance,
    }