from typing import Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from app.learning.trainer import SemanticMapper


router = APIRouter(
    prefix="/api/learning",
    tags=["Learning"],
)


SUPPORTED_VENDORS = {
    "cisco_ios",
    "pfsense",
}


_mapper: Optional[SemanticMapper] = None


def get_mapper() -> SemanticMapper:
    """
    Lazily create the semantic mapper.

    Lazy initialization prevents the SentenceTransformer model from
    loading during application import.
    """
    global _mapper

    if _mapper is None:
        _mapper = SemanticMapper()

    return _mapper


def _validate_vendor(vendor: str) -> None:
    if vendor not in SUPPORTED_VENDORS:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Unsupported learning vendor '{vendor}'. "
                f"Supported vendors: {sorted(SUPPORTED_VENDORS)}"
            ),
        )


class SuggestRequest(BaseModel):
    vendor: str = Field(
        min_length=1,
        max_length=50,
    )
    source_text: str = Field(
        min_length=1,
        max_length=2000,
    )
    top_k: int = Field(
        default=3,
        ge=1,
        le=5,
    )


class SuggestResponse(BaseModel):
    vendor: str
    source_text: str
    suggestions: List[Dict[str, object]]


class ConfirmRequest(BaseModel):
    vendor: str = Field(
        min_length=1,
        max_length=50,
    )
    source_text: str = Field(
        min_length=1,
        max_length=2000,
    )
    control_id: str = Field(
        min_length=1,
        max_length=100,
    )
    target_key: str = Field(
        min_length=1,
        max_length=200,
    )
    score: float = Field(
        ge=0.0,
        le=1.0,
    )
    rationale: Optional[str] = Field(
        default=None,
        max_length=2000,
    )
    confirmed_by: str = Field(
        default="human",
        min_length=1,
        max_length=100,
    )


class ConfirmResponse(BaseModel):
    mapping: Dict[str, object]


class MappingsResponse(BaseModel):
    mappings: List[Dict[str, object]]
    count: int


@router.post(
    "/suggest",
    response_model=SuggestResponse,
)
def suggest_mapping(request: SuggestRequest):
    """
    Return AI-generated candidate mappings.

    Suggestions are read-only. Nothing is persisted here.
    """
    _validate_vendor(request.vendor)

    mapper = get_mapper()

    suggestions = mapper.suggest(
        vendor=request.vendor,
        source_text=request.source_text,
        top_k=request.top_k,
    )

    return {
        "vendor": request.vendor,
        "source_text": request.source_text,
        "suggestions": suggestions,
    }


@router.post(
    "/confirm",
    response_model=ConfirmResponse,
)
def confirm_mapping(request: ConfirmRequest):
    """
    Persist a human-confirmed mapping.
    """
    _validate_vendor(request.vendor)

    mapper = get_mapper()

    candidate = {
        "control_id": request.control_id,
        "target_key": request.target_key,
        "score": request.score,
        "description": (
            request.rationale
            or "Human-confirmed mapping."
        ),
    }

    saved_mapping = mapper.confirm(
        vendor=request.vendor,
        source_text=request.source_text,
        candidate=candidate,
        confirmed_by=request.confirmed_by,
    )

    return {
        "mapping": saved_mapping,
    }


@router.get(
    "/mappings",
    response_model=MappingsResponse,
)
def list_mappings(
    vendor: Optional[str] = Query(
        default=None,
        min_length=1,
        max_length=50,
    )
):
    """
    List persisted human-confirmed mappings.
    """
    if vendor is not None:
        _validate_vendor(vendor)

    mapper = get_mapper()

    mappings = mapper.store.list_mappings(
        vendor=vendor
    )

    return {
        "mappings": mappings,
        "count": len(mappings),
    }