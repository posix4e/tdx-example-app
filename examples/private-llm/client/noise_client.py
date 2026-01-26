"""
Noise Protocol Client for E2E Encrypted Communication

This module provides a Noise Protocol client that:
1. Establishes E2E encrypted WebSocket connection to server
2. Verifies server's TDX attestation with session binding
3. Ensures encrypted channel connects to the attested TEE

Usage:
    from noise_client import NoiseClient

    client = NoiseClient(
        host="ws://localhost:8080",
        server_pubkey="<hex pubkey from discovery>",
    )
    client.connect()

    # Get attestation with session binding proof
    attestation = client.get_attestation()

    # Verify session binding
    if client.verify_session_binding(attestation):
        # Safe to send sensitive data
        response = client.send_request({"type": "chat", "payload": {...}})
"""

import hashlib
import json
import logging
import threading
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric import ed25519
from noise.connection import NoiseConnection, Keypair
from websocket import WebSocket, create_connection

logger = logging.getLogger(__name__)

NOISE_PROTOCOL = b"Noise_NK_25519_ChaChaPoly_SHA256"


@dataclass
class SessionBinding:
    """Session binding proof from server attestation."""

    session_hash: bytes
    signature: bytes
    binding_pubkey: bytes


class NoiseClient:
    """
    Noise Protocol client with WebSocket transport.

    This client establishes an E2E encrypted channel using
    Noise NK pattern, where the client knows the server's
    static public key in advance.

    The server authenticates via TDX attestation + session binding,
    not via Noise authentication. This allows the client to verify
    that the encrypted channel terminates inside the attested TEE.
    """

    def __init__(
        self,
        host: str,
        server_pubkey: str | bytes,
        ws_path: str = "/ws/noise",
    ):
        """
        Initialize Noise client.

        Args:
            host: Server host (e.g., "ws://localhost:8080" or "wss://example.com")
            server_pubkey: Server's Noise static public key (hex string or bytes)
            ws_path: WebSocket endpoint path
        """
        self.host = host.rstrip("/")
        self.ws_path = ws_path
        self._ws: WebSocket | None = None
        self._noise: NoiseConnection | None = None
        self._handshake_complete = False
        self._lock = threading.Lock()

        # Parse server public key
        if isinstance(server_pubkey, str):
            self._server_pubkey = bytes.fromhex(server_pubkey)
        else:
            self._server_pubkey = server_pubkey

    @property
    def url(self) -> str:
        """Full WebSocket URL."""
        return f"{self.host}{self.ws_path}"

    @property
    def connected(self) -> bool:
        """Check if connected and handshake complete."""
        return self._ws is not None and self._handshake_complete

    def connect(self, timeout: float = 30.0):
        """
        Connect and perform Noise NK handshake.

        Args:
            timeout: Connection timeout in seconds

        Raises:
            ConnectionError: If connection or handshake fails
        """
        with self._lock:
            if self._handshake_complete:
                return

            logger.info(f"Connecting to {self.url}")

            # Create WebSocket connection
            self._ws = create_connection(self.url, timeout=timeout)

            # Initialize Noise as initiator
            self._noise = NoiseConnection.from_name(NOISE_PROTOCOL)
            self._noise.set_as_initiator()
            self._noise.set_keypair_from_public_bytes(
                Keypair.REMOTE_STATIC,
                self._server_pubkey,
            )
            self._noise.start_handshake()

            # Send handshake message
            client_hello = self._noise.write_message()
            logger.debug(f"Sending handshake: {len(client_hello)} bytes")
            self._ws.send_binary(client_hello)

            # Receive server response
            server_response = self._ws.recv()
            if isinstance(server_response, str):
                server_response = server_response.encode()
            logger.debug(f"Received handshake response: {len(server_response)} bytes")

            # Process response (completes handshake)
            self._noise.read_message(server_response)
            self._handshake_complete = True

            logger.info("Noise handshake complete, channel established")

    def close(self):
        """Close the connection."""
        with self._lock:
            if self._ws:
                try:
                    self._ws.close()
                except Exception:
                    pass
                self._ws = None
            self._noise = None
            self._handshake_complete = False

    def get_handshake_hash(self) -> bytes:
        """
        Get the handshake hash for session binding verification.

        Returns:
            32-byte handshake hash
        """
        if not self._noise or not self._handshake_complete:
            raise RuntimeError("Not connected")
        return self._noise.get_handshake_hash()

    def send_request(self, request: dict, timeout: float = 120.0) -> dict:
        """
        Send encrypted request and receive response.

        Args:
            request: Request dict to send
            timeout: Response timeout in seconds

        Returns:
            Response dict from server
        """
        if not self.connected:
            raise RuntimeError("Not connected")

        with self._lock:
            # Encrypt and send
            plaintext = json.dumps(request).encode()
            ciphertext = self._noise.encrypt(plaintext)
            self._ws.send_binary(ciphertext)

            # Receive and decrypt
            self._ws.settimeout(timeout)
            response_ciphertext = self._ws.recv()
            if isinstance(response_ciphertext, str):
                response_ciphertext = response_ciphertext.encode()

            response_plaintext = self._noise.decrypt(response_ciphertext)
            return json.loads(response_plaintext)

    def get_attestation(self) -> dict:
        """
        Request attestation from server over encrypted channel.

        Returns:
            Attestation dict with session_binding
        """
        response = self.send_request({"type": "get_attestation"})
        if response.get("type") == "error":
            raise RuntimeError(f"Server error: {response.get('payload', {}).get('error')}")
        return response.get("payload", {})

    def verify_session_binding(
        self,
        attestation: dict,
        expected_mrtd: str | None = None,
    ) -> bool:
        """
        Verify session binding proves this channel connects to attested TEE.

        This is the critical security check:
        1. Verify the binding_pubkey hash matches REPORTDATA in the TDX quote
        2. Verify the signature over the session hash is valid
        3. Optionally verify MRTD matches expected

        Args:
            attestation: Attestation dict from get_attestation()
            expected_mrtd: Optional expected MRTD to verify

        Returns:
            True if verification succeeds

        Raises:
            ValueError: If verification fails with reason
        """
        session_binding = attestation.get("session_binding", {})
        if not session_binding:
            raise ValueError("No session_binding in attestation")

        # Extract binding components
        try:
            server_session_hash = bytes.fromhex(session_binding["session_hash"])
            signature = bytes.fromhex(session_binding["signature"])
            binding_pubkey = bytes.fromhex(session_binding["binding_pubkey"])
        except (KeyError, ValueError) as e:
            raise ValueError(f"Invalid session_binding format: {e}") from e

        # Step 1: Verify our session hash matches server's
        our_session_hash = self.get_handshake_hash()
        if our_session_hash != server_session_hash:
            raise ValueError(
                f"Session hash mismatch: ours={our_session_hash.hex()[:16]}, "
                f"server={server_session_hash.hex()[:16]}"
            )

        # Step 2: Verify signature over session hash
        try:
            public_key = ed25519.Ed25519PublicKey.from_public_bytes(binding_pubkey)
            public_key.verify(signature, server_session_hash)
        except Exception as e:
            raise ValueError(f"Session binding signature invalid: {e}") from e

        # Step 3: Verify binding_pubkey hash matches REPORTDATA
        measurements = attestation.get("measurements", {})
        report_data = measurements.get("report_data", "")

        expected_reportdata = hashlib.sha512(binding_pubkey).hexdigest()
        if report_data != expected_reportdata:
            raise ValueError(
                f"REPORTDATA mismatch: quote has {report_data[:32]}..., "
                f"expected {expected_reportdata[:32]}... from binding_pubkey"
            )

        # Step 4: Optionally verify MRTD
        if expected_mrtd:
            mrtd = attestation.get("mrtd") or measurements.get("mrtd")
            if mrtd != expected_mrtd:
                raise ValueError(f"MRTD mismatch: expected {expected_mrtd}, got {mrtd}")

        logger.info("Session binding verification successful")
        return True

    def chat(self, messages: list[dict], model: str | None = None) -> dict:
        """
        Send chat request over encrypted channel.

        Args:
            messages: List of message dicts with role and content
            model: Optional model name

        Returns:
            Response dict with message
        """
        payload = {"messages": messages}
        if model:
            payload["model"] = model

        response = self.send_request({"type": "chat", "payload": payload})
        if response.get("type") == "error":
            raise RuntimeError(f"Chat error: {response.get('payload', {}).get('error')}")
        return response.get("payload", {})

    def __enter__(self):
        """Context manager entry."""
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()
        return False


def verify_intel_ta_token(token: str) -> dict:
    """
    Verify Intel Trust Authority JWT token.

    In production, this would:
    1. Fetch Intel TA's signing keys from their JWKS endpoint
    2. Verify the JWT signature
    3. Check token expiration
    4. Return parsed claims

    For now, we just parse the claims without cryptographic verification.
    The actual Intel TA verification happens on the server side.

    Args:
        token: JWT token from Intel TA

    Returns:
        Parsed TDX claims from token
    """
    import base64

    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Invalid JWT format")

    # Decode payload
    payload = parts[1]
    padding = 4 - len(payload) % 4
    if padding != 4:
        payload += "=" * padding
    payload = payload.replace("-", "+").replace("_", "/")

    claims = json.loads(base64.b64decode(payload))

    # Extract TDX-specific claims
    tdx_claims = claims.get("tdx", {})
    return {
        "mrtd": tdx_claims.get("tdx_mrtd"),
        "rtmr0": tdx_claims.get("tdx_rtmr0"),
        "rtmr1": tdx_claims.get("tdx_rtmr1"),
        "rtmr2": tdx_claims.get("tdx_rtmr2"),
        "rtmr3": tdx_claims.get("tdx_rtmr3"),
        "report_data": tdx_claims.get("tdx_report_data"),
        "tcb_status": tdx_claims.get("attester_tcb_status"),
    }
