"""
TDX Example App - Simple Confidential Service

This service runs inside a TDX VM. Attestation and EasyEnclave registration
are handled at the VM level by the launcher, not in the application code.
"""

from datetime import datetime
from fastapi import FastAPI


app = FastAPI(
    title="TDX Example App",
    description="Simple service running in TDX VM",
    version="1.0.0",
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
