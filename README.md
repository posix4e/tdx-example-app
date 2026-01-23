# TDX Example App

A simple service demonstrating deployment in Intel TDX with hardware attestation.

Attestation is handled at the **VM level** by the [tdx_github_runner](https://github.com/posix4e/tdx_github_runner) launcher - no attestation code needed in your application.

## Quick Start

### Run Ephemeral Build with Attestation

```yaml
# .github/workflows/build.yml
- uses: posix4e/tdx_github_runner/.github/actions/measure-tdx@main
  with:
    docker_compose_path: './docker-compose.yml'
    intel_api_key: ${{ secrets.INTEL_API_KEY }}
```

### Deploy Persistent TDX VM

```yaml
# .github/workflows/deploy.yml
- uses: posix4e/tdx_github_runner/.github/actions/launch-tdx@main
  with:
    vm_name: 'my-service'
    docker_compose_path: './docker-compose.yml'
```

## How It Works

```
┌─────────────────────────────────────────────────────────────┐
│                    GitHub Actions                           │
│  ┌─────────────────┐     ┌─────────────────┐               │
│  │ measure-tdx     │     │ launch-tdx      │               │
│  │ (ephemeral)     │     │ (persistent)    │               │
│  └────────┬────────┘     └────────┬────────┘               │
└───────────┼───────────────────────┼─────────────────────────┘
            │                       │
            ▼                       ▼
┌───────────────────────────────────────────────────────────┐
│                    TDX Host                               │
│  ┌─────────────────────────────────────────────────────┐ │
│  │ TDX VM (launcher handles attestation)              │ │
│  │  ┌─────────────────────────────────────────────┐   │ │
│  │  │ Docker Container                            │   │ │
│  │  │  - Your app (no attestation code needed)    │   │ │
│  │  │  - Just expose /health endpoint             │   │ │
│  │  └─────────────────────────────────────────────┘   │ │
│  └─────────────────────────────────────────────────────┘ │
└───────────────────────────────────────────────────────────┘
```

## Files

```
tdx-example-app/
├── .github/workflows/
│   ├── measure-build.yml    # Ephemeral build with attestation
│   └── deploy-service.yml   # Deploy persistent VM
├── app/
│   ├── main.py              # Simple FastAPI service
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

## License

MIT
