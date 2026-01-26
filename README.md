# TDX Example App

A simple service demonstrating deployment in Intel TDX with hardware attestation.

## How It Works

```
                    Your CI/CD Pipeline
  ┌───────────────────────────────────────────────────────┐
  │ POST /api/v1/deployments                              │
  │   { agent_id, compose, config }                       │
  └───────────────────────────────────────────────────────┘
                        │
                        ▼
┌───────────────────────────────────────────────────────────┐
│                 EasyEnclave Control Plane                 │
│  - Stores deployment configs                              │
│  - Tracks agent status (undeployed/deployed)              │
│  - Handles service registration                           │
└───────────────────────┬───────────────────────────────────┘
                        │ (agent polls)
                        ▼
┌───────────────────────────────────────────────────────────┐
│                    TDX Host                               │
│  ┌─────────────────────────────────────────────────────┐  │
│  │ TDX VM (Launcher Agent)                             │  │
│  │  - Polls control plane for work                     │  │
│  │  - Pulls docker-compose configs                     │  │
│  │  - Generates attestation                            │  │
│  │  - Self-updates from GitHub                         │  │
│  │  ┌─────────────────────────────────────────────┐    │  │
│  │  │ Your App Container                          │    │  │
│  │  │  - Just expose /health endpoint             │    │  │
│  │  └─────────────────────────────────────────────┘    │  │
│  └─────────────────────────────────────────────────────┘  │
└───────────────────────────────────────────────────────────┘
```

## Quick Start

### Prerequisites

1. Get an Agent ID from your TDX infrastructure admin or the EasyEnclave dashboard
2. Set GitHub repository variables:
   - `EASYENCLAVE_URL`: Control plane URL (e.g., `https://app.easyenclave.com`)
   - `CI_AGENT_ID`: Agent ID for CI builds (optional, for measure-build workflow)
3. Set GitHub secrets:
   - `INTEL_API_KEY`: Intel Trust Authority API key

### Deploy via GitHub Actions

Trigger the "Deploy Service" workflow manually:

1. Go to Actions > Deploy Service
2. Enter the Agent ID and Service URL
3. Click "Run workflow"

### Deploy via API

```bash
# Encode compose file
COMPOSE=$(base64 -w0 docker-compose.yml)

# Submit deployment
curl -X POST https://app.easyenclave.com/api/v1/deployments \
  -H "Content-Type: application/json" \
  -d "{
    \"agent_id\": \"your-agent-id\",
    \"compose\": \"$COMPOSE\",
    \"config\": {
      \"service_name\": \"my-app\",
      \"service_url\": \"https://my-app.example.com\",
      \"health_endpoint\": \"/health\",
      \"intel_api_key\": \"your-intel-api-key\"
    }
  }"

# Poll for completion
curl https://app.easyenclave.com/api/v1/deployments/{deployment_id}
```

### Deploy in GitHub Actions Workflow

```yaml
- name: Deploy to TDX
  run: |
    COMPOSE=$(base64 -w0 docker-compose.yml)

    RESPONSE=$(curl -s -X POST "${{ vars.EASYENCLAVE_URL }}/api/v1/deployments" \
      -H "Content-Type: application/json" \
      -d "{
        \"agent_id\": \"${{ vars.AGENT_ID }}\",
        \"compose\": \"$COMPOSE\",
        \"config\": {
          \"service_name\": \"my-app\",
          \"health_endpoint\": \"/health\"
        }
      }")

    DEPLOYMENT_ID=$(echo "$RESPONSE" | jq -r '.deployment_id')

    # Wait for completion
    while true; do
      STATUS=$(curl -s "${{ vars.EASYENCLAVE_URL }}/api/v1/deployments/$DEPLOYMENT_ID" | jq -r '.status')
      if [ "$STATUS" = "completed" ]; then break; fi
      if [ "$STATUS" = "failed" ]; then exit 1; fi
      sleep 10
    done
```

## API Reference

See [EasyEnclave API Docs](https://app.easyenclave.com/docs) for full API reference.

### Key Endpoints

| Endpoint | Description |
|----------|-------------|
| `POST /api/v1/deployments` | Submit a deployment |
| `GET /api/v1/deployments/{id}` | Check deployment status |
| `GET /api/v1/agents` | List available agents |
| `GET /api/v1/agents/{id}` | Get agent details |
| `POST /api/v1/agents/{id}/undeploy` | Reset agent to undeployed |
| `GET /api/v1/services` | Discover deployed services |

## Files

```
tdx-example-app/
├── .github/workflows/
│   ├── deploy-service.yml    # Deploy to TDX agent
│   └── measure-build.yml     # Build with attestation
├── app/
│   ├── main.py               # Simple FastAPI service
│   └── requirements.txt
├── docker-compose.yml
├── Dockerfile
└── README.md
```

## Local Development

```bash
# Run locally
docker compose up --build

# Test endpoints
curl http://localhost:8080/health
curl http://localhost:8080/info
```

## Architecture

### Pull-Based Deployment

Unlike traditional push-based deployments, EasyEnclave uses a pull-based model:

1. **TDX VMs boot as "launcher agents"** - They start in an undeployed state
2. **Agents register with control plane** - On boot, they generate attestation and register
3. **CI/CD submits deployments to API** - Your workflow posts to `/api/v1/deployments`
4. **Agents poll and execute** - Agents pick up deployments and run docker compose
5. **Attestation is automatic** - VM-level attestation happens after workload health check

### Why Pull-Based?

- **No SSH/network access to VMs needed** - Agents pull configs, not pushed to them
- **Centralized deployment tracking** - All state in control plane
- **Self-updating agents** - Agents can update themselves from GitHub
- **Reusable agents** - Undeploy and redeploy without rebooting VMs

## License

MIT
