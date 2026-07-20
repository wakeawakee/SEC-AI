"""FastAPI bridge for the React AI Security Assurance interface.

This file deliberately reuses the secured engine in ``app.py`` instead of
duplicating compliance logic. The browser gets a streaming-style API response
while the LangChain, Chroma, sanitization, and Pydantic logic stay in one
shared backend module.
"""

from __future__ import annotations

import asyncio
import os
import urllib.error
import urllib.request
from functools import lru_cache
from typing import Literal

from fastapi import FastAPI, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from app import (
    DOCUMENT_TASK,
    SECAI_CHAT_TASK,
    build_vector_store,
    policy_fingerprint,
    run_analysis,
    run_structured_document_assessment,
    sanitize_sensitive_data,
    uploaded_text,
    _policy_files,
)


Provider = Literal["Mock (offline)", "Ollama (local)", "OpenAI"]
Mode = Literal["chat", "document"]


class AnalyzeRequest(BaseModel):
    """Browser payload for chat or document-readiness analysis."""

    message: str = Field(default="", max_length=80_000)
    mode: Mode = "chat"
    provider: Provider = "Mock (offline)"
    model: str = "deterministic-rules"
    document_text: str = Field(default="", max_length=250_000)


class UploadedFileAdapter:
    """Expose FastAPI UploadFile bytes through the interface app.uploaded_text expects."""

    def __init__(self, name: str, data: bytes):
        self.name = name
        self._data = data

    def getvalue(self) -> bytes:
        return self._data


app = FastAPI(
    title="SECAI Security Assurance API",
    version="1.0.0",
    description="Streaming API for sanitized RAG-backed ISO/SOC/AI compliance assessment.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def _api_key_for(provider: Provider) -> str:
    """Keep secrets server-side; the React app never receives model credentials."""

    if provider == "OpenAI":
        return os.environ.get("OPENAI_API_KEY", "")
    return ""


def _model_name(provider: Provider, requested: str) -> str:
    if provider == "Mock (offline)":
        return "deterministic-rules"
    if requested.strip():
        return requested.strip()
    return "gpt-4o-mini" if provider == "OpenAI" else "llama3.2"


@lru_cache(maxsize=8)
def _store_for(provider: Provider, model_name: str, api_key_present: bool):
    """Cache the local policy index per provider/model configuration."""

    del api_key_present
    api_key = _api_key_for(provider)
    fingerprint = policy_fingerprint(_policy_files())
    return build_vector_store(fingerprint, provider, model_name, api_key)


def _chunk_markdown(text: str, chunk_size: int = 48):
    """Small text chunks create a token-stream feel without changing the engine."""

    for index in range(0, len(text), chunk_size):
        yield text[index : index + chunk_size]


async def _stream_text(text: str):
    for chunk in _chunk_markdown(text):
        yield chunk
        await asyncio.sleep(0.01)


def _ollama_guidance(error: Exception | None = None) -> str:
    base_url = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")
    details = f" Backend OLLAMA_BASE_URL is `{base_url}`."
    if error:
        details += f" Low-level error: `{type(error).__name__}: {error}`."
    return (
        "Ollama is not reachable from the FastAPI Docker container."
        + details
        + " If you run Ollama on the host, start it with "
        "`OLLAMA_HOST=0.0.0.0:11434 ollama serve` so containers can reach it, "
        "and ensure `nomic-embed-text` plus your chat model are pulled. "
        "Alternatively run the Docker sidecar with "
        "`docker compose -f docker-compose.yml -f docker-compose.ollama.yml up --build`."
    )


@app.get("/health")
def health() -> dict[str, str]:
    return {
        "status": "ok",
        "engine": "sanitized-rag",
        "default_provider": "Mock (offline)",
    }


@app.get("/ollama-health")
def ollama_health() -> dict[str, object]:
    """Check whether the API container can reach the configured Ollama endpoint."""

    base_url = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434").rstrip("/")
    try:
        with urllib.request.urlopen(f"{base_url}/api/tags", timeout=5) as response:
            return {
                "reachable": True,
                "base_url": base_url,
                "status": response.status,
            }
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return {
            "reachable": False,
            "base_url": base_url,
            "error": f"{type(exc).__name__}: {exc}",
            "remediation": _ollama_guidance(exc),
        }


@app.post("/analyze")
async def analyze(payload: AnalyzeRequest) -> StreamingResponse:
    """Run a sanitized chat/document assessment and stream markdown to the browser."""

    api_key = _api_key_for(payload.provider)
    if payload.provider == "OpenAI" and not api_key:
        raise HTTPException(
            status_code=400,
            detail="OPENAI_API_KEY must be configured on the backend server.",
        )

    model_name = _model_name(payload.provider, payload.model)
    try:
        store = _store_for(payload.provider, model_name, bool(api_key))
    except Exception as exc:
        if payload.provider == "Ollama (local)":
            raise HTTPException(status_code=503, detail=_ollama_guidance(exc)) from exc
        raise
    raw_text = payload.document_text.strip() or payload.message
    if not raw_text.strip():
        raise HTTPException(status_code=400, detail="No message or document text supplied.")

    try:
        if payload.mode == "document":
            result, sources, _ = run_structured_document_assessment(
                raw_text,
                store,
                payload.provider,
                model_name,
                api_key,
            )
        else:
            safe_message = sanitize_sensitive_data(payload.message)
            if payload.document_text:
                safe_message += "\n\nATTACHED DOCUMENT:\n" + sanitize_sensitive_data(payload.document_text)
            result, sources = run_analysis(
                SECAI_CHAT_TASK,
                safe_message,
                store,
                payload.provider,
                model_name,
                api_key,
            )
    except Exception as exc:
        if payload.provider == "Ollama (local)":
            raise HTTPException(status_code=503, detail=_ollama_guidance(exc)) from exc
        raise

    if sources:
        result += "\n\n---\n**Retrieved policy sources:** " + ", ".join(sources)
    return StreamingResponse(_stream_text(result), media_type="text/markdown")


@app.post("/analyze-upload")
async def analyze_upload(
    file: UploadFile,
    message: str = "",
    provider: Provider = "Mock (offline)",
    model: str = "deterministic-rules",
) -> StreamingResponse:
    """Accept a PDF/DOCX/TXT-style evidence file and stream structured assessment."""

    data = await file.read()
    adapter = UploadedFileAdapter(file.filename or "uploaded-evidence", data)
    try:
        document_text = uploaded_text(adapter)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    payload = AnalyzeRequest(
        message=message or f"Assess uploaded evidence file: {adapter.name}",
        mode="document",
        provider=provider,
        model=model,
        document_text=document_text,
    )
    return await analyze(payload)
