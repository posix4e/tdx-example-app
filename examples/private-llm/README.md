# Private LLM Proxy with Noise Protocol E2E Encryption

A Python-based confidential LLM inference service with **end-to-end encryption that terminates inside the TEE**, similar to [Confer Proxy](https://github.com/ConferLabs/confer-proxy).

## Key Security Feature: E2E Encryption Inside TEE

Unlike traditional HTTPS (which terminates at the host), this implementation uses **Noise Protocol** to ensure encryption terminates **inside the TDX Trust Domain**:

```
┌──────────────────────┐                    ┌─────────────────────────────────────┐
│       Client         │                    │          TDX Trust Domain           │
│                      │                    │  ┌─────────────────────────────────┐│
│  ┌────────────────┐  │   Noise Protocol   │  │      Private LLM Proxy          ││
│  │ Noise Client   │◀─┼────────────────────┼──│  ┌─────────────────────────┐    ││
│  │                │  │   (E2E Encrypted)  │  │  │   Noise Server          │    ││
│  │ 1. Handshake   │  │                    │  │  │   - Terminates inside   │    ││
│  │ 2. Get attst   │  │                    │  │  │   - Binds to attestation│    ││
│  │ 3. Verify      │  │                    │  │  └───────────┬─────────────┘    ││
│  │ 4. Send prompt │  │                    │  │              │                  ││
│  └────────────────┘  │                    │  │              ▼                  ││
│                      │                    │  │  ┌─────────────────────────┐    ││
└──────────────────────┘                    │  │  │       Ollama            │    ││
                                            │  │  │   (Local LLM)           │    ││
         Host cannot decrypt                │  │  └─────────────────────────┘    ││
         traffic - it's E2E                 │  └─────────────────────────────────┘│
                                            └─────────────────────────────────────┘
```

**Why This Matters**: Even if an attacker controls the host OS, they cannot:
- Decrypt your prompts (Noise private key only exists in TEE memory)
- MITM the connection (session binding proves you're connected to the attested TEE)
- See LLM responses (encrypted all the way to your client)

## Security Flow

```
Client                                              Proxy (in TEE)
   │                                                      │
   │  1. Noise NK Handshake (client knows proxy pubkey)   │
   │─────────────────────────────────────────────────────▶│
   │                                                      │
   │  2. Handshake response + session established         │
   │◀─────────────────────────────────────────────────────│
   │                                                      │
   │  3. Request attestation (over Noise channel)         │
   │─────────────────────────────────────────────────────▶│
   │                                                      │
   │  4. Return: {attestation, session_binding}           │
   │◀─────────────────────────────────────────────────────│
   │      - attestation: TDX quote + Intel TA JWT         │
   │      - session_binding: sign(session_hash, key)      │
   │        where key is bound to attestation             │
   │                                                      │
   │  5. Client verifies:                                 │
   │     a. Intel TA JWT is valid                         │
   │     b. MRTD matches expected                         │
   │     c. session_binding proves THIS session           │
   │        connects to the attested enclave              │
   │                                                      │
   │  6. Send encrypted prompt (safe - verified E2E)      │
   │─────────────────────────────────────────────────────▶│
   │                                                      │
   │  7. Receive encrypted response                       │
   │◀─────────────────────────────────────────────────────│
```

## Deployment

This service **must** be deployed in a TDX Trust Domain. It requires:
- Intel TDX hardware
- Access to `/sys/kernel/config/tsm/report` for attestation
- Intel Trust Authority API key for attestation verification

```bash
# Deploy in TDX
tdx deploy \
  --service-name "private-llm" \
  --service-url "https://llm.example.com" \
  --compose examples/private-llm/docker-compose.yml \
  --intel-api-key $INTEL_API_KEY
```

## Using the Verified Client

```python
from client.verified_llm import VerifiedLLMClient

# Option 1: Direct connection with known pubkey
client = VerifiedLLMClient(
    service_url="wss://llm.example.com",
    noise_pubkey="<pubkey from service discovery>",
    expected_mrtd="<expected MRTD for verification>",
)

# Option 2: Discover via EasyEnclave
client = VerifiedLLMClient.from_easyenclave(
    service_name="private-llm",
    easyenclave_url="https://app.easyenclave.com",
)

# Connect, verify attestation, and establish E2E encrypted channel
result = client.connect_and_verify()
if result.secure:
    print(f"Session bound: {result.session_bound}")
    print(f"Intel verified: {result.intel_verified}")
    print(f"MRTD: {result.mrtd}")

    # Now safe to chat - E2E encrypted to verified TEE
    response = client.chat("What is the capital of France?")
    print(response)
```

## API Endpoints

| Endpoint | Transport | Description |
|----------|-----------|-------------|
| `GET /health` | Plain HTTP | Health check with Noise pubkey |
| `GET /attestation` | Plain HTTP | Basic attestation info |
| `WS /ws/noise` | **Noise E2E** | Encrypted WebSocket channel |
| `POST /v1/chat/completions` | Plain HTTP | OpenAI-compatible (NOT encrypted) |

**Recommended**: Use `/ws/noise` for all sensitive operations. The plain HTTP endpoints are provided for monitoring only.

## Message Protocol (over Noise channel)

After establishing a Noise connection, send JSON messages:

```json
// Request attestation
{"type": "get_attestation"}

// Attestation response (includes session binding)
{
    "type": "attestation",
    "payload": {
        "quote_b64": "base64...",
        "intel_ta_token": "jwt...",
        "mrtd": "hex...",
        "session_binding": {
            "session_hash": "hex...",
            "signature": "hex...",
            "binding_pubkey": "hex..."
        }
    }
}

// Chat request
{
    "type": "chat",
    "payload": {
        "messages": [{"role": "user", "content": "Hello!"}]
    }
}

// Chat response
{
    "type": "chat_response",
    "payload": {
        "message": {"role": "assistant", "content": "..."}
    }
}
```

## Session Binding Explained

The session binding proof is what makes this secure:

1. **Binding Key Generation**: Server generates Ed25519 keypair
2. **REPORTDATA**: Hash of public key goes into TDX quote's REPORTDATA field
3. **Quote Generation**: TDX quote includes REPORTDATA (binding to this key)
4. **Intel Verification**: Intel TA verifies the quote
5. **Session Signing**: Server signs the Noise session hash with binding key

Client verification:
1. Check Intel TA token is valid
2. Verify REPORTDATA == hash(binding_pubkey)
3. Verify signature(session_hash, binding_pubkey) is valid
4. **This proves the Noise channel connects to the attested TEE**

## Files

| File | Description |
|------|-------------|
| `app/main.py` | FastAPI server with WebSocket Noise endpoint |
| `app/noise_server.py` | Noise Protocol server implementation |
| `app/attestation.py` | TDX attestation with binding key |
| `client/noise_client.py` | Noise Protocol WebSocket client |
| `client/verified_llm.py` | High-level verified LLM client |

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `OLLAMA_HOST` | `http://ollama:11434` | Ollama server URL |
| `MODEL_NAME` | `qwen2.5:0.5b` | Default model |
| `INTEL_API_KEY` | *required* | Intel Trust Authority API key |
| `INTEL_API_URL` | `https://api.trustauthority.intel.com` | Intel TA URL |

## Dependencies

**Server (in TEE)**:
- `noiseprotocol>=0.3.1` - Noise Protocol implementation
- `cryptography>=41.0.0` - Ed25519 for binding keys
- `fastapi`, `uvicorn` - Web framework

**Client**:
- `noiseprotocol>=0.3.1` - Noise Protocol implementation
- `cryptography>=41.0.0` - Signature verification
- `websocket-client>=1.6.0` - WebSocket client

## How This Differs from Previous Approach

| Previous (HTTPS) | New (Noise Protocol) |
|------------------|----------------------|
| TLS terminates at host | Encryption terminates inside TEE |
| Host could MITM | Host cannot decrypt traffic |
| Attestation checked separately | Attestation bound to session |
| Trust TLS certificates | Trust TEE attestation |

## How This Differs from Confer

| Feature | Confer | This Implementation |
|---------|--------|---------------------|
| Language | Java | Python |
| TEE | AMD SEV-SNP | Intel TDX |
| E2E Protocol | Noise | Noise |
| LLM Backend | Custom | Ollama |
| Attestation | Custom chain | EasyEnclave + Intel TA |

## Security Considerations

- **E2E Encryption**: Traffic is encrypted from client to inside TEE
- **Session Binding**: Proves the channel connects to attested code
- **Model Protection**: Weights are inside TEE memory
- **Prompt Privacy**: Prompts are encrypted, never visible to host
- **Response Privacy**: Generated inside TEE, encrypted to client
- **Forward Secrecy**: Each session uses ephemeral keys
- **No Fallbacks**: Service will not start without real TDX attestation
