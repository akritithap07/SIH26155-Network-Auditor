from fastapi import APIRouter, File, HTTPException, UploadFile

from app.parsers.detector import detect_vendor


router = APIRouter(
    prefix="/api",
    tags=["Configuration"],
)


MAX_FILE_SIZE = 2 * 1024 * 1024  # 2 MB


@router.post("/upload")
async def upload_configuration(file: UploadFile = File(...)):
    """
    Upload a network configuration file and detect its vendor.
    """

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
            detail="Configuration file is too large. Maximum size is 2 MB.",
        )

    try:
        config_text = content.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise HTTPException(
            status_code=400,
            detail="Configuration file must be UTF-8 text.",
        )

    detection = detect_vendor(config_text)

    return {
        "filename": file.filename,
        "content_type": file.content_type,
        "size_bytes": len(content),
        "line_count": len(config_text.splitlines()),
        **detection,
    }