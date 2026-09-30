import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Set

from fastapi import APIRouter, File, HTTPException, UploadFile

from app.api.training import get_mapper
from app.compliance.engine import run_compliance
from app.normalization.schema import UnrecognizedEntry
from app.parsers.cisco_parser import CiscoIOSParser
from app.parsers.detector import detect_vendor
from app.parsers.pfsense_parser import PfSenseParser
from app.shadow_rules.engine import analyze_shadow_rules


router = APIRouter(
    prefix="/api",
    tags=["Analysis"],
)


MAX_FILE_SIZE = 2 * 1024 * 1024
AI_TOP_K = 3


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


def _serialize_xml_element(
    element: ET.Element,
) -> str:
    return ET.tostring(
        element,
        encoding="unicode",
    ).strip()


def _collect_pfsense_unknown_rule_entries(
    config_text: str,
) -> List[UnrecognizedEntry]:
    """
    Conservatively expose unsupported direct children of pfSense
    firewall rules as learning candidates.
    """
    try:
        root = ET.fromstring(config_text)
    except ET.ParseError:
        return []

    filter_node = root.find("./filter")

    if filter_node is None:
        return []

    known_rule_children: Set[str] = {
        "type",
        "descr",
        "interface",
        "direction",
        "protocol",
        "log",
        "disabled",
        "source",
        "destination",
    }

    entries: List[UnrecognizedEntry] = []

    for rule_index, rule_node in enumerate(
        filter_node.findall("./rule"),
        start=1,
    ):
        for child in list(rule_node):
            tag = child.tag

            if not isinstance(tag, str):
                continue

            if tag in known_rule_children:
                continue

            serialized = _serialize_xml_element(
                child
            )

            if not serialized:
                continue

            entries.append(
                UnrecognizedEntry(
                    line_number=None,
                    text=serialized,
                    context=f"filter.rule[{rule_index}]",
                    evidence=serialized,
                )
            )

    return entries


def _merge_unknown_entries(
    vendor: str,
    normalized: Any,
    config_text: str,
) -> List[UnrecognizedEntry]:
    merged = list(
        normalized.unrecognized_entries
    )

    if vendor == "pfsense":
        merged.extend(
            _collect_pfsense_unknown_rule_entries(
                config_text
            )
        )

    deduplicated: List[UnrecognizedEntry] = []
    seen = set()

    for entry in merged:
        identity = (
            entry.line_number,
            entry.text,
            entry.context,
        )

        if identity in seen:
            continue

        seen.add(identity)
        deduplicated.append(entry)

    return deduplicated


def _build_ai_assistance(
    vendor: str,
    unknown_entries: List[UnrecognizedEntry],
) -> Dict[str, Any]:
    """
    Generate advisory mappings for unrecognized entries.

    AI never changes the deterministic compliance result.
    """
    if not unknown_entries:
        return {
            "status": "not_needed",
            "entry_count": 0,
            "impact_on_compliance": "none",
            "entries": [],
        }

    try:
        mapper = get_mapper()
    except Exception:
        return {
            "status": "unavailable",
            "entry_count": len(unknown_entries),
            "impact_on_compliance": "none",
            "entries": [
                {
                    "line_number": entry.line_number,
                    "text": entry.text,
                    "context": entry.context,
                    "suggestions": [],
                    "message": (
                        "AI mapping is temporarily "
                        "unavailable."
                    ),
                }
                for entry in unknown_entries
            ],
        }

    results: List[Dict[str, Any]] = []
    has_error = False

    for entry in unknown_entries:
        try:
            suggestions = mapper.suggest(
                vendor=vendor,
                source_text=entry.text,
                top_k=AI_TOP_K,
            )

            results.append(
                {
                    "line_number": entry.line_number,
                    "text": entry.text,
                    "context": entry.context,
                    "suggestions": suggestions,
                }
            )

        except Exception:
            has_error = True

            results.append(
                {
                    "line_number": entry.line_number,
                    "text": entry.text,
                    "context": entry.context,
                    "suggestions": [],
                    "message": (
                        "AI mapping could not be "
                        "completed for this entry."
                    ),
                }
            )

    return {
        "status": (
            "degraded"
            if has_error
            else "available"
        ),
        "entry_count": len(unknown_entries),
        "impact_on_compliance": "none",
        "entries": results,
    }


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
        normalized = parser.parse(
            config_text
        )
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
    Complete audit pipeline:

    upload
    -> vendor detection
    -> vendor-specific parsing
    -> normalization
    -> deterministic compliance evaluation
    -> shadow rule detection
    -> AI suggestions for unrecognized entries

    Shadow Rule Detection and AI assistance are advisory
    analyses and do not modify PASS, FAIL, or NOT_ASSESSED.
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
            "shadow_rules": {
                "status": "not_available",
                "rule_count": 0,
                "issues": [],
                "summary": {
                    "critical": 0,
                    "medium": 0,
                    "total": 0,
                },
            },
            "ai_assistance": {
                "status": "not_available",
                "entry_count": 0,
                "impact_on_compliance": "none",
                "entries": [],
            },
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

        shadow_rules = analyze_shadow_rules(
            normalized.firewall_rules
        )

    except (TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=422,
            detail=str(exc),
        ) from exc

    unknown_entries = _merge_unknown_entries(
        vendor=vendor,
        normalized=normalized,
        config_text=config_text,
    )

    ai_assistance = _build_ai_assistance(
        vendor=vendor,
        unknown_entries=unknown_entries,
    )

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
        "shadow_rules": shadow_rules,
        "ai_assistance": ai_assistance,
    }