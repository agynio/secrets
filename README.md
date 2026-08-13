# Secrets Service

Secrets is a gRPC service for managing secret providers and secrets backed by
PostgreSQL. It currently supports resolving secrets from HashiCorp Vault KV v2
using a remote name in the form `<mount>/<path>/<key>`.

## Build

Proto stubs are generated via Buf and are gitignored under `gen/go`.

```bash
buf generate buf.build/agynio/api --path agynio/api/secrets/v1
buf generate buf.build/agynio/api --path agynio/api/egress/v1
go build ./...
```

## Run

The service applies database migrations on startup and exposes the gRPC server
on the configured address.

```bash
export DATABASE_URL='postgres://user:pass@localhost:5432/secrets?sslmode=disable'
export GRPC_ADDRESS=':50051'
go run ./cmd/secrets
```

## Configuration

| Environment variable | Required | Default | Description |
| --- | --- | --- | --- |
| `DATABASE_URL` | Yes | - | PostgreSQL connection string. |
| `GRPC_ADDRESS` | No | `:50051` | Address for the gRPC server to listen on. |
| `ENCRYPTION_KEY_FILE` | Yes | - | Path to the encryption key file used for local secret values. |
| `EGRESS_RULES_GRPC_TARGET` | No | - | EgressRules gRPC target used to fail-closed on `DeleteSecret` when egress rules reference a secret. |
| `LLM_GRPC_TARGET` | No | - | LLM gRPC target, same purpose for subscriptions holding a secret by reference. |
| `IMAGES_GRPC_TARGET` | No | - | Images gRPC target, same purpose for images naming a secret as their registry credential. |

## Repository Layout

- `cmd/secrets` - service entrypoint.
- `internal/server` - gRPC handlers and request validation.
- `internal/store` - Postgres access layer and pagination helpers.
- `internal/vault` - Vault KV v2 client.
- `internal/db` / `migrations` - migration runner and SQL migrations.
- `charts/secrets` - Helm chart for Kubernetes deployments.

## Helm Chart

The Helm chart lives in `charts/secrets` and supports setting the database URL
inline or via an existing secret.

```bash
helm install secrets charts/secrets \
  --set image.tag=0.1.0 \
  --set database.url='postgres://user:pass@postgres:5432/secrets?sslmode=disable'
```

To use an existing secret instead of a plain URL:

```bash
helm install secrets charts/secrets \
  --set image.tag=0.1.0 \
  --set database.existingSecret.name=secrets-db \
  --set database.existingSecret.key=database-url
```
