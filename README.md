# Secrets Service

Secrets is a gRPC service that manages secret providers and secret metadata in
Postgres, and resolves secret values from HashiCorp Vault KV v2.

## What it does
- Stores secret providers (currently Vault) and secret metadata in Postgres.
- Resolves secret values by reading Vault KV v2 paths like
  `<mount>/<path>/<key>`.
- Supports pagination and search on list APIs.

## Build & Run

### Prerequisites
- Go 1.25.x
- Postgres
- Vault (for ResolveSecret)

### Build
```bash
make build
```

### Test & Lint
```bash
make test
make lint
```

### Run locally
```bash
export DATABASE_URL=postgres://user:pass@localhost:5432/secrets?sslmode=disable
export GRPC_ADDRESS=:50051

go run ./cmd/secrets
```

The service applies database migrations on startup and listens on
`GRPC_ADDRESS` (defaults to `:50051`).

### Generate protobuf stubs
```bash
make proto
```
This expects the secrets proto to be available in `buf.build/agynio/api`.

## Configuration
| Variable | Required | Description |
| --- | --- | --- |
| `DATABASE_URL` | yes | Postgres connection string |
| `GRPC_ADDRESS` | no | gRPC bind address (default `:50051`) |

## Repository structure
- `cmd/secrets` — main entrypoint
- `internal/config` — environment parsing
- `internal/store` — Postgres data access
- `internal/server` — gRPC handlers and conversions
- `internal/vault` — Vault KV v2 client
- `migrations` — SQL migrations
- `charts/secrets` — Helm chart
- `gen/go` — generated protobuf stubs (gitignored)

## Helm chart

Install with a direct database URL:
```bash
helm install secrets charts/secrets \
  --set image.tag=0.1.0 \
  --set database.url='postgres://user:pass@db:5432/secrets?sslmode=disable'
```

Or use an existing Secret:
```bash
helm install secrets charts/secrets \
  --set image.tag=0.1.0 \
  --set database.existingSecret.name=secrets-db \
  --set database.existingSecret.key=database-url
```
