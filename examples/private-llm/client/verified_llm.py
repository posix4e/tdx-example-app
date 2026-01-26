"""
Verified LLM Client - E2E Encrypted Communication with Attestation Binding

This client implements the secure verification flow:
1. Discover service via EasyEnclave (get Noise pubkey and expected MRTD)
2. Establish Noise Protocol E2E encrypted channel
3. Request attestation WITH session binding over encrypted channel
4. Verify session binding proves THIS channel connects to verified TEE
5. ONLY THEN send prompts (encrypted, verified E2E)

Security Properties:
- E2E encryption terminates INSIDE the TEE (host cannot decrypt)
- Session binding proves the channel connects to the attested code
- MRTD verification ensures expected code is running
- Intel TA JWT provides independent attestation verification

This prevents MITM attacks - even by the host OS - because:
1. Noise encryption uses server's private key (only in TEE memory)
2. Session binding cryptographically ties the channel to attestation
"""

import logging
from dataclasses import dataclass

import requests

from noise_client import NoiseClient, verify_intel_ta_token

logger = logging.getLogger(__name__)


@dataclass
class VerificationResult:
    """Result of attestation verification with session binding."""

    verified: bool
    service_url: str
    noise_pubkey: str
    mrtd: str | None
    intel_verified: bool
    session_bound: bool
    error: str | None = None

    @property
    def secure(self) -> bool:
        """True if fully secure (verified, Intel attested, session bound)."""
        return self.verified and self.intel_verified and self.session_bound


class VerifiedLLMClient:
    """
    LLM client with E2E encryption and attestation binding.

    This client ensures your prompts are:
    1. Encrypted end-to-end via Noise Protocol
    2. Only sent to verified TDX-protected services
    3. Cryptographically bound to the attestation

    Example:
        # Option 1: Direct connection (you provide Noise pubkey)
        client = VerifiedLLMClient(
            service_url="ws://localhost:8080",
            noise_pubkey="<hex pubkey>",
            expected_mrtd="<optional expected mrtd>",
        )

        # Option 2: Discovery via EasyEnclave
        client = VerifiedLLMClient.from_easyenclave(
            service_name="private-llm",
            easyenclave_url="https://app.easyenclave.com",
        )

        # Connect and verify
        result = client.connect_and_verify()
        if not result.secure:
            raise SecurityError(f"Verification failed: {result.error}")

        # Now safe to chat - traffic is E2E encrypted to verified TEE
        response = client.chat("What is the meaning of life?")
        print(response)
    """

    def __init__(
        self,
        service_url: str,
        noise_pubkey: str,
        expected_mrtd: str | None = None,
    ):
        """
        Initialize verified LLM client.

        Args:
            service_url: WebSocket URL (ws:// or wss://)
            noise_pubkey: Server's Noise public key (hex)
            expected_mrtd: Expected MRTD to verify against
        """
        self.service_url = service_url
        self.noise_pubkey = noise_pubkey
        self.expected_mrtd = expected_mrtd

        self._noise_client: NoiseClient | None = None
        self._verification_result: VerificationResult | None = None

    @classmethod
    def from_easyenclave(
        cls,
        service_name: str,
        easyenclave_url: str = "https://app.easyenclave.com",
        expected_mrtd: str | None = None,
    ) -> "VerifiedLLMClient":
        """
        Create client by discovering service from EasyEnclave.

        Args:
            service_name: Name of service in EasyEnclave
            easyenclave_url: EasyEnclave API URL
            expected_mrtd: Override expected MRTD (uses EasyEnclave's if not provided)

        Returns:
            Configured VerifiedLLMClient
        """
        logger.info(f"Discovering service '{service_name}' from EasyEnclave...")

        resp = requests.get(
            f"{easyenclave_url.rstrip('/')}/api/v1/services",
            params={"name": service_name},
            timeout=10,
        )
        resp.raise_for_status()

        services = resp.json().get("services", [])
        if not services:
            raise ValueError(f"Service '{service_name}' not found in EasyEnclave")

        service = services[0]
        service_url = service.get("endpoints", {}).get("prod", "")
        noise_pubkey = service.get("noise_pubkey", "")
        mrtd = expected_mrtd or service.get("mrtd")

        if not service_url:
            raise ValueError("Service has no endpoint URL")
        if not noise_pubkey:
            raise ValueError("Service has no Noise public key")

        # Convert HTTP URL to WebSocket URL
        ws_url = service_url.replace("https://", "wss://").replace("http://", "ws://")

        logger.info(f"Discovered service at {ws_url}")
        logger.info(f"Noise pubkey: {noise_pubkey[:32]}...")
        if mrtd:
            logger.info(f"Expected MRTD: {mrtd[:32]}...")

        return cls(
            service_url=ws_url,
            noise_pubkey=noise_pubkey,
            expected_mrtd=mrtd,
        )

    @property
    def connected(self) -> bool:
        """Check if connected and verified."""
        return (
            self._noise_client is not None
            and self._noise_client.connected
            and self._verification_result is not None
            and self._verification_result.verified
        )

    def connect_and_verify(self) -> VerificationResult:
        """
        Connect and verify the service.

        This performs the full security verification:
        1. Establish Noise E2E encrypted channel
        2. Request attestation over encrypted channel
        3. Verify session binding
        4. Verify MRTD if expected
        5. Verify Intel TA token if required

        Returns:
            VerificationResult with verification status
        """
        # Step 1: Create Noise client and connect
        logger.info("Establishing Noise Protocol channel...")
        self._noise_client = NoiseClient(
            host=self.service_url,
            server_pubkey=self.noise_pubkey,
        )

        try:
            self._noise_client.connect()
        except Exception as e:
            return VerificationResult(
                verified=False,
                service_url=self.service_url,
                noise_pubkey=self.noise_pubkey,
                mrtd=None,
                intel_verified=False,
                session_bound=False,
                error=f"Connection failed: {e}",
            )

        # Step 2: Get attestation over encrypted channel
        logger.info("Requesting attestation over encrypted channel...")
        try:
            attestation = self._noise_client.get_attestation()
        except Exception as e:
            self._noise_client.close()
            return VerificationResult(
                verified=False,
                service_url=self.service_url,
                noise_pubkey=self.noise_pubkey,
                mrtd=None,
                intel_verified=False,
                session_bound=False,
                error=f"Failed to get attestation: {e}",
            )

        mrtd = attestation.get("mrtd")
        intel_ta_token = attestation.get("intel_ta_token")

        # Step 3: Verify session binding
        logger.info("Verifying session binding...")
        session_bound = False
        try:
            self._noise_client.verify_session_binding(
                attestation,
                expected_mrtd=self.expected_mrtd,
            )
            session_bound = True
            logger.info("Session binding verified - channel connects to attested TEE")
        except ValueError as e:
            error_msg = str(e)
            logger.warning(f"Session binding verification failed: {error_msg}")
            self._noise_client.close()
            return VerificationResult(
                verified=False,
                service_url=self.service_url,
                noise_pubkey=self.noise_pubkey,
                mrtd=mrtd,
                intel_verified=False,
                session_bound=False,
                error=f"Session binding failed: {error_msg}",
            )

        # Step 4: Verify Intel TA token (required)
        intel_verified = False
        if not intel_ta_token:
            self._noise_client.close()
            return VerificationResult(
                verified=False,
                service_url=self.service_url,
                noise_pubkey=self.noise_pubkey,
                mrtd=mrtd,
                intel_verified=False,
                session_bound=session_bound,
                error="Intel TA token missing - server must provide attestation",
            )

        try:
            claims = verify_intel_ta_token(intel_ta_token)
            intel_verified = True
            logger.info(f"Intel TA token verified, MRTD: {claims.get('mrtd', 'N/A')[:16]}...")
        except Exception as e:
            self._noise_client.close()
            return VerificationResult(
                verified=False,
                service_url=self.service_url,
                noise_pubkey=self.noise_pubkey,
                mrtd=mrtd,
                intel_verified=False,
                session_bound=session_bound,
                error=f"Intel TA token verification failed: {e}",
            )

        # All checks passed
        self._verification_result = VerificationResult(
            verified=True,
            service_url=self.service_url,
            noise_pubkey=self.noise_pubkey,
            mrtd=mrtd,
            intel_verified=intel_verified,
            session_bound=session_bound,
        )

        logger.info("Verification complete - service is secure")
        return self._verification_result

    def _ensure_verified(self):
        """Ensure service is connected and verified."""
        if not self.connected:
            raise RuntimeError(
                "Not connected and verified. Call connect_and_verify() first."
            )

    def chat(
        self,
        message: str,
        system_prompt: str | None = None,
        model: str | None = None,
    ) -> str:
        """
        Send chat message over verified E2E encrypted channel.

        Args:
            message: User message
            system_prompt: Optional system prompt
            model: Optional model name

        Returns:
            Assistant's response text
        """
        self._ensure_verified()

        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": message})

        result = self._noise_client.chat(messages, model=model)
        return result.get("message", {}).get("content", "")

    def chat_messages(
        self,
        messages: list[dict],
        model: str | None = None,
    ) -> dict:
        """
        Send multi-turn conversation over verified E2E encrypted channel.

        Args:
            messages: List of message dicts with role and content
            model: Optional model name

        Returns:
            Full response dict including message, model, token counts
        """
        self._ensure_verified()
        return self._noise_client.chat(messages, model=model)

    def close(self):
        """Close the connection."""
        if self._noise_client:
            self._noise_client.close()
            self._noise_client = None
        self._verification_result = None

    def __enter__(self):
        """Context manager entry - connects and verifies."""
        result = self.connect_and_verify()
        if not result.verified:
            raise RuntimeError(f"Verification failed: {result.error}")
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()
        return False


# Example usage
if __name__ == "__main__":
    import sys

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    # Parse arguments
    if len(sys.argv) < 3:
        print("Usage: python verified_llm.py <ws://host:port> <noise_pubkey_hex> [expected_mrtd]")
        print("       python verified_llm.py --easyenclave <service_name> [easyenclave_url]")
        sys.exit(1)

    if sys.argv[1] == "--easyenclave":
        service_name = sys.argv[2]
        easyenclave_url = sys.argv[3] if len(sys.argv) > 3 else "https://app.easyenclave.com"
        client = VerifiedLLMClient.from_easyenclave(service_name, easyenclave_url)
    else:
        service_url = sys.argv[1]
        noise_pubkey = sys.argv[2]
        expected_mrtd = sys.argv[3] if len(sys.argv) > 3 else None
        client = VerifiedLLMClient(
            service_url=service_url,
            noise_pubkey=noise_pubkey,
            expected_mrtd=expected_mrtd,
        )

    print("=" * 60)
    print("VERIFIED LLM CLIENT - E2E Encrypted with Attestation Binding")
    print("=" * 60)
    print()

    # Connect and verify
    print("Step 1: Establishing Noise Protocol E2E encrypted channel...")
    print("Step 2: Requesting attestation over encrypted channel...")
    print("Step 3: Verifying session binding...")
    print()

    result = client.connect_and_verify()

    print(f"Verification Result:")
    print(f"  Verified:       {result.verified}")
    print(f"  Session Bound:  {result.session_bound}")
    print(f"  Intel Verified: {result.intel_verified}")
    print(f"  MRTD:           {result.mrtd[:32] if result.mrtd else 'N/A'}...")
    print()

    if not result.verified:
        print(f"VERIFICATION FAILED: {result.error}")
        print("NOT sending any prompts to unverified service!")
        sys.exit(1)

    print("Service VERIFIED - E2E encrypted channel established")
    print()

    # Now safe to chat
    print("Sending test prompt over verified encrypted channel...")
    print()

    response = client.chat(
        "Hello! Please confirm you're running in a secure TDX enclave.",
        system_prompt="You are a helpful assistant running inside a secure TDX Trust Domain.",
    )

    print(f"Response: {response}")
    print()

    # Cleanup
    client.close()
    print("Connection closed.")
