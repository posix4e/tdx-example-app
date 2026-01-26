"""
Private LLM Proxy - Confidential AI Inference with E2E Encryption

This service provides:
1. TDX Trust Domain isolation - hardware-enforced memory encryption
2. Noise Protocol E2E encryption - terminates INSIDE the TEE, not at host
3. Session binding to attestation - proves encrypted channel connects to verified TEE
4. Local LLM inference via Ollama - prompts never leave the secure environment

Architecture:
    Client                                          Proxy (in TEE)
       │                                                  │
       │  GET /health (plain HTTP for monitoring)         │
       │─────────────────────────────────────────────────▶│
       │                                                  │
       │  WebSocket /ws/noise (Noise protocol)            │
       │══════════════════════════════════════════════════│
       │  [Handshake] ──▶ session established             │
       │  [Encrypted] get_attestation ──▶ attestation     │
       │  [Encrypted] chat ──▶ LLM response               │
       │                                                  │

The host OS cannot decrypt Noise traffic because the private key
exists only in TEE memory.
"""

import hashlib
import json
import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path

import httpx
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from attestation import BoundAttestation, generate_bound_attestation
from noise_server import NOISE_PROTOCOL, NoiseServer, NoiseSession, handle_noise_message


def get_intel_api_key() -> str:
    """Get Intel API key from environment or launcher config."""
    # First try environment variable
    key = os.getenv("INTEL_API_KEY")
    if key:
        return key

    # Try launcher config file (mounted share directory)
    config_paths = [
        Path("/share/config.json"),  # Standard share mount
        Path("/app/config.json"),    # Alternative location
    ]
    for config_path in config_paths:
        if config_path.exists():
            try:
                config = json.loads(config_path.read_text())
                key = config.get("intel_api_key")
                if key:
                    return key
            except Exception:
                pass

    raise RuntimeError("INTEL_API_KEY not found in environment or config file")


# Configuration
OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")
MODEL_NAME = os.getenv("MODEL_NAME", "qwen2.5:0.5b")
INTEL_API_KEY = get_intel_api_key()
INTEL_API_URL = os.getenv("INTEL_API_URL", "https://api.trustauthority.intel.com")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Global state
noise_server: NoiseServer | None = None
attestation: BoundAttestation | None = None
model_ready = False


class ChatMessage(BaseModel):
    role: str
    content: str


class ChatRequest(BaseModel):
    messages: list[ChatMessage]
    model: str | None = None
    stream: bool = False
    temperature: float | None = None
    max_tokens: int | None = None


class GenerateRequest(BaseModel):
    prompt: str
    model: str | None = None
    stream: bool = False


async def pull_model_if_needed():
    """Pull the model on startup if not present."""
    global model_ready
    async with httpx.AsyncClient(timeout=600.0) as client:
        try:
            resp = await client.get(f"{OLLAMA_HOST}/api/tags")
            if resp.status_code == 200:
                models = resp.json().get("models", [])
                model_names = [m.get("name", "") for m in models]
                if MODEL_NAME not in model_names and not any(MODEL_NAME in n for n in model_names):
                    logger.info(f"Pulling model {MODEL_NAME}...")
                    resp = await client.post(
                        f"{OLLAMA_HOST}/api/pull",
                        json={"name": MODEL_NAME},
                        timeout=1800.0,
                    )
                    if resp.status_code == 200:
                        logger.info(f"Model {MODEL_NAME} pulled successfully")
                    else:
                        logger.warning(f"Failed to pull model: {resp.text}")
                else:
                    logger.info(f"Model {MODEL_NAME} already available")
                model_ready = True
        except Exception as e:
            logger.warning(f"Could not check/pull model: {e}")


async def initialize_attestation():
    """Generate TDX attestation with binding key on startup."""
    global attestation, noise_server

    attestation = generate_bound_attestation(
        intel_api_key=INTEL_API_KEY,
        intel_api_url=INTEL_API_URL,
    )
    logger.info("TDX attestation generated successfully")

    noise_server = NoiseServer(attestation)
    logger.info(f"Noise server ready, pubkey: {noise_server.get_public_key()[:32]}...")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize attestation and pull model on startup."""
    await initialize_attestation()
    await pull_model_if_needed()
    yield


app = FastAPI(
    title="Private LLM Proxy",
    description="Confidential LLM inference with E2E encryption via Noise Protocol",
    version="2.0.0",
    lifespan=lifespan,
)


def compute_code_hash() -> str:
    """Compute hash of source files for transparency."""
    try:
        source = Path(__file__).read_bytes()
        return hashlib.sha256(source).hexdigest()
    except Exception:
        return "unknown"


# =============================================================================
# Plain HTTP Endpoints (for monitoring/discovery)
# =============================================================================


@app.get("/")
async def root():
    """Root endpoint with service info."""
    return {
        "service": "Private LLM Proxy",
        "version": "2.0.0",
        "description": "Confidential LLM inference with Noise Protocol E2E encryption",
        "model": MODEL_NAME,
        "noise_protocol": NOISE_PROTOCOL.decode(),
        "noise_pubkey": noise_server.get_public_key() if noise_server else None,
        "endpoints": {
            "/health": "Health check (plain HTTP)",
            "/ws/noise": "WebSocket with Noise Protocol (E2E encrypted)",
            "/v1/chat/completions": "OpenAI-compatible (plain HTTP - NOT recommended)",
        },
    }


@app.get("/health")
async def health():
    """
    Health check endpoint (plain HTTP for monitoring).

    This endpoint is intentionally unencrypted for:
    - Load balancer health checks
    - Monitoring systems
    - Basic connectivity tests

    Sensitive data should use /ws/noise.
    """
    ollama_ok = False
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"{OLLAMA_HOST}/")
            ollama_ok = resp.status_code == 200
    except Exception:
        pass

    status = "healthy" if ollama_ok and model_ready else "starting"

    return {
        "status": status,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "ollama": "connected" if ollama_ok else "disconnected",
        "model": MODEL_NAME,
        "model_ready": model_ready,
        "noise_ready": noise_server is not None,
        "noise_pubkey": noise_server.get_public_key() if noise_server else None,
    }


@app.get("/attestation")
async def get_attestation():
    """
    Get attestation info (plain HTTP).

    NOTE: For verified attestation with session binding,
    use the /ws/noise endpoint and request "get_attestation".
    This endpoint provides basic info for discovery.
    """
    if not attestation:
        raise HTTPException(status_code=503, detail="Attestation not ready")

    return {
        "service": "Private LLM Proxy",
        "code_hash": compute_code_hash(),
        "model": MODEL_NAME,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tee_type": "TDX",
        "noise_pubkey": noise_server.get_public_key() if noise_server else None,
        "mrtd": attestation.measurements.get("mrtd"),
        "binding_pubkey": attestation.binding_key.public_bytes().hex(),
        "has_intel_token": attestation.intel_ta_token is not None,
        "note": "For session-bound attestation, use /ws/noise endpoint",
    }


# =============================================================================
# WebSocket Noise Protocol Endpoint (E2E Encrypted)
# =============================================================================


@app.websocket("/ws/noise")
async def noise_websocket(websocket: WebSocket):
    """
    WebSocket endpoint for Noise Protocol E2E encrypted communication.

    Protocol:
    1. Client sends Noise NK handshake message (binary)
    2. Server responds with handshake completion (binary)
    3. All subsequent messages are encrypted via Noise

    Message format (after handshake):
        Request:  {"type": "chat", "payload": {"messages": [...]}}
        Response: {"type": "chat_response", "payload": {...}}
    """
    if not noise_server:
        await websocket.close(code=1011, reason="Server not ready")
        return

    await websocket.accept()
    session: NoiseSession | None = None

    try:
        # Step 1: Receive handshake from client
        client_hello = await websocket.receive_bytes()
        logger.info(f"Received Noise handshake: {len(client_hello)} bytes")

        # Step 2: Complete handshake
        session, server_response = noise_server.handshake(client_hello)
        await websocket.send_bytes(server_response)
        logger.info("Noise handshake complete, channel established")

        # Step 3: Handle encrypted messages
        while True:
            ciphertext = await websocket.receive_bytes()
            request = session.recv_json(ciphertext)
            logger.debug(f"Received request type: {request.get('type')}")

            response = await handle_noise_message(
                request=request,
                session=session,
                server=noise_server,
                chat_handler=handle_chat_internal,
            )

            await websocket.send_bytes(session.send_json(response))

    except WebSocketDisconnect:
        logger.info("Client disconnected")
    except Exception as e:
        logger.exception(f"Noise session error: {e}")
        try:
            if session and session.handshake_complete:
                error_response = {"type": "error", "payload": {"error": str(e)}}
                await websocket.send_bytes(session.send_json(error_response))
        except Exception:
            pass
        await websocket.close(code=1011, reason=str(e))


async def handle_chat_internal(payload: dict) -> dict:
    """
    Internal chat handler called from Noise message handler.

    Args:
        payload: Chat request payload with messages, model, etc.

    Returns:
        Response dict with assistant message
    """
    messages = payload.get("messages", [])
    model = payload.get("model", MODEL_NAME)
    stream = payload.get("stream", False)

    if stream:
        # Streaming not yet supported over Noise
        # Would need to send multiple encrypted frames
        raise ValueError("Streaming not supported over Noise channel")

    ollama_request = {
        "model": model,
        "messages": messages,
        "stream": False,
    }

    if payload.get("temperature") is not None:
        ollama_request["options"] = {"temperature": payload["temperature"]}

    async with httpx.AsyncClient(timeout=120.0) as client:
        resp = await client.post(f"{OLLAMA_HOST}/api/chat", json=ollama_request)
        if resp.status_code != 200:
            raise HTTPException(status_code=resp.status_code, detail=resp.text)

        ollama_resp = resp.json()
        return {
            "message": ollama_resp.get("message", {}),
            "model": model,
            "prompt_tokens": ollama_resp.get("prompt_eval_count", 0),
            "completion_tokens": ollama_resp.get("eval_count", 0),
        }


# =============================================================================
# Plain HTTP Chat Endpoints (for backward compatibility)
# NOTE: These do NOT provide E2E encryption - use /ws/noise for security
# =============================================================================


@app.post("/v1/chat/completions")
async def chat_completions(request: ChatRequest):
    """
    OpenAI-compatible chat completions endpoint.

    WARNING: This endpoint uses plain HTTP. For E2E encryption,
    use the /ws/noise WebSocket endpoint instead.
    """
    model = request.model or MODEL_NAME

    ollama_request = {
        "model": model,
        "messages": [{"role": m.role, "content": m.content} for m in request.messages],
        "stream": request.stream,
    }
    if request.temperature is not None:
        ollama_request["options"] = {"temperature": request.temperature}

    async with httpx.AsyncClient(timeout=120.0) as client:
        if request.stream:
            async def stream_response():
                async with client.stream(
                    "POST",
                    f"{OLLAMA_HOST}/api/chat",
                    json=ollama_request,
                ) as resp:
                    async for chunk in resp.aiter_bytes():
                        yield chunk

            return StreamingResponse(stream_response(), media_type="application/x-ndjson")
        else:
            resp = await client.post(f"{OLLAMA_HOST}/api/chat", json=ollama_request)
            if resp.status_code != 200:
                raise HTTPException(status_code=resp.status_code, detail=resp.text)

            ollama_resp = resp.json()
            return {
                "id": f"chatcmpl-{datetime.now().timestamp()}",
                "object": "chat.completion",
                "created": int(datetime.now().timestamp()),
                "model": model,
                "choices": [
                    {
                        "index": 0,
                        "message": ollama_resp.get("message", {}),
                        "finish_reason": "stop",
                    }
                ],
                "usage": {
                    "prompt_tokens": ollama_resp.get("prompt_eval_count", 0),
                    "completion_tokens": ollama_resp.get("eval_count", 0),
                    "total_tokens": (
                        ollama_resp.get("prompt_eval_count", 0)
                        + ollama_resp.get("eval_count", 0)
                    ),
                },
            }


@app.post("/api/generate")
async def generate(request: GenerateRequest):
    """Ollama-compatible generate endpoint (plain HTTP)."""
    model = request.model or MODEL_NAME

    async with httpx.AsyncClient(timeout=120.0) as client:
        if request.stream:
            async def stream_response():
                async with client.stream(
                    "POST",
                    f"{OLLAMA_HOST}/api/generate",
                    json={"model": model, "prompt": request.prompt, "stream": True},
                ) as resp:
                    async for chunk in resp.aiter_bytes():
                        yield chunk

            return StreamingResponse(stream_response(), media_type="application/x-ndjson")
        else:
            resp = await client.post(
                f"{OLLAMA_HOST}/api/generate",
                json={"model": model, "prompt": request.prompt, "stream": False},
            )
            if resp.status_code != 200:
                raise HTTPException(status_code=resp.status_code, detail=resp.text)
            return resp.json()


@app.post("/api/chat")
async def chat(request: ChatRequest):
    """Ollama-compatible chat endpoint (plain HTTP)."""
    model = request.model or MODEL_NAME

    ollama_request = {
        "model": model,
        "messages": [{"role": m.role, "content": m.content} for m in request.messages],
        "stream": request.stream,
    }

    async with httpx.AsyncClient(timeout=120.0) as client:
        if request.stream:
            async def stream_response():
                async with client.stream(
                    "POST",
                    f"{OLLAMA_HOST}/api/chat",
                    json=ollama_request,
                ) as resp:
                    async for chunk in resp.aiter_bytes():
                        yield chunk

            return StreamingResponse(stream_response(), media_type="application/x-ndjson")
        else:
            resp = await client.post(f"{OLLAMA_HOST}/api/chat", json=ollama_request)
            if resp.status_code != 200:
                raise HTTPException(status_code=resp.status_code, detail=resp.text)
            return resp.json()


@app.get("/api/tags")
async def list_models():
    """List available models."""
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.get(f"{OLLAMA_HOST}/api/tags")
        if resp.status_code != 200:
            raise HTTPException(status_code=resp.status_code, detail=resp.text)
        return resp.json()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8080)
