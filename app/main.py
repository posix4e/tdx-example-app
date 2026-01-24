"""
TDX Example App - Simple Confidential Service

This service runs inside a TDX VM. Attestation is handled at the VM level
by the launcher, not in the application code.
"""

import os
import json
from datetime import datetime
from fastapi import FastAPI
from contextlib import asynccontextmanager


async def register_with_discovery():
    """Register this service with EasyEnclave discovery on startup."""
    discovery_url = os.getenv("EASYENCLAVE_URL", "https://app.easyenclave.com")
    service_url = os.getenv("SERVICE_URL", "")

    if not service_url:
        print("SERVICE_URL not set, skipping discovery registration")
        return

    try:
        from easyenclave import EasyEnclaveClient

        # Try to read attestation data if available
        attestation_json = None
        mrtd = None
        intel_ta_token = None

        attestation_path = os.getenv("ATTESTATION_PATH", "/app/attestation.json")
        if os.path.exists(attestation_path):
            try:
                with open(attestation_path) as f:
                    attestation_json = json.load(f)
                    mrtd = attestation_json.get("mrtd")
                    intel_ta_token = attestation_json.get("intel_ta_token")
            except Exception as e:
                print(f"Could not read attestation data: {e}")

        client = EasyEnclaveClient(discovery_url, verify_attestation=False)
        service_id = client.register(
            name="tdx-example-app",
            endpoints={"prod": service_url},
            description="Example TDX-attested application",
            source_repo="https://github.com/easyenclave/tdx-example-app",
            source_commit=os.getenv("GIT_COMMIT", ""),
            tags=["example", "tdx", "demo"],
            attestation_json=attestation_json,
            mrtd=mrtd,
            intel_ta_token=intel_ta_token,
        )
        print(f"Registered with EasyEnclave discovery: {service_id}")
        client.close()
    except Exception as e:
        print(f"Failed to register with discovery: {e}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan context manager for startup/shutdown."""
    await register_with_discovery()
    yield


app = FastAPI(
    title="TDX Example App",
    description="Simple service running in TDX VM",
    version="1.0.0",
    lifespan=lifespan,
)


@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "service": "TDX Example App",
        "version": "1.0.0",
        "message": "Running inside a TDX Trust Domain",
        "endpoints": {
            "/health": "Health check",
            "/info": "Service info",
        }
    }


@app.get("/health")
async def health():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }


@app.get("/info")
async def info():
    """Service information"""
    return {
        "service": "TDX Example App",
        "description": "This service runs in a TDX Trust Domain",
        "attestation": "Handled at VM level by launcher",
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
