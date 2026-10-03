"""HTTP routes for Module 1 (HAR analyzer)."""

from __future__ import annotations

import json
import re
from pathlib import PurePath
from typing import Annotated, Any

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status
from fastapi.responses import Response

from oktatrace.config import Settings, get_settings
from oktatrace.har_analyzer import HarAnalysisResult, HarParseError, analyze_har, load_har, redact_har
from oktatrace.har_analyzer.sample_har import SAMPLE_HAR_FILENAME, build_sample_har

router = APIRouter(prefix="/api/har", tags=["HAR analyzer"])

SettingsDep = Annotated[Settings, Depends(get_settings)]
HarUpload = Annotated[UploadFile, File(description="A .har file (synthetic data only)")]


def _download_name(filename: str | None, suffix: str) -> str:
    """Build a safe attachment filename from an uploaded name."""
    stem = re.sub(r"[^A-Za-z0-9._-]", "_", PurePath(filename or "upload").stem)[:64] or "upload"
    return f"{stem}{suffix}"


def _json_attachment(payload: Any, filename: str, extra_headers: dict[str, str] | None = None) -> Response:
    headers = {"Content-Disposition": f'attachment; filename="{filename}"', **(extra_headers or {})}
    return Response(
        content=json.dumps(payload, indent=2, ensure_ascii=False),
        media_type="application/json",
        headers=headers,
    )


async def _read_har(upload: UploadFile, settings: Settings) -> dict[str, Any]:
    """Read an upload with a size cap and parse it as HAR."""
    data = await upload.read(settings.max_har_bytes + 1)
    if len(data) > settings.max_har_bytes:
        raise HTTPException(
            status_code=413,  # constant name differs across Starlette versions
            detail=f"HAR exceeds the {settings.max_har_bytes // (1024 * 1024)} MB limit",
        )
    try:
        return load_har(data)
    except HarParseError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.post("/analyze", response_model=HarAnalysisResult, summary="Analyse an uploaded HAR")
async def analyze_upload(file: HarUpload, settings: SettingsDep) -> HarAnalysisResult:
    """Return findings for an uploaded HAR. The file is processed in memory and not stored."""
    har = await _read_har(file, settings)
    return analyze_har(har, long_lived_threshold_seconds=settings.long_lived_threshold_seconds)


@router.post("/redact", summary="Download a redacted copy of an uploaded HAR")
async def redact_upload(file: HarUpload, settings: SettingsDep) -> Response:
    """Return the HAR with every secret masked, as a file download."""
    har = await _read_har(file, settings)
    result = redact_har(har)
    return _json_attachment(
        result.har,
        _download_name(file.filename, ".redacted.har"),
        {"X-OktaTrace-Redactions": str(result.redaction_count)},
    )


@router.get("/sample", summary="Download the synthetic sample HAR")
def download_sample() -> Response:
    """Serve the bundled synthetic HAR (it intentionally contains fake secrets)."""
    return _json_attachment(build_sample_har(), SAMPLE_HAR_FILENAME)


@router.get("/sample/analysis", response_model=HarAnalysisResult, summary="Analyse the sample HAR")
def analyze_sample(settings: SettingsDep) -> HarAnalysisResult:
    """Analyse the bundled synthetic HAR without needing an upload."""
    return analyze_har(
        build_sample_har(), long_lived_threshold_seconds=settings.long_lived_threshold_seconds
    )


@router.get("/sample/redacted", summary="Download the redacted sample HAR")
def download_redacted_sample() -> Response:
    """Serve the sample HAR after redaction."""
    result = redact_har(build_sample_har())
    return _json_attachment(
        result.har,
        _download_name(SAMPLE_HAR_FILENAME, ".redacted.har"),
        {"X-OktaTrace-Redactions": str(result.redaction_count)},
    )
