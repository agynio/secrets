ALTER TABLE secrets
    ALTER COLUMN secret_provider_id DROP NOT NULL,
    ADD COLUMN encrypted_value BYTEA;

CREATE TABLE image_pull_secrets (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id     UUID NOT NULL,
    description         TEXT NOT NULL DEFAULT '',
    registry            TEXT NOT NULL,
    username            TEXT NOT NULL,
    encrypted_value     BYTEA,
    value_provider_id   UUID REFERENCES secret_providers(id) ON DELETE RESTRICT,
    value_reference     TEXT NOT NULL DEFAULT '',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_image_pull_secrets_organization ON image_pull_secrets (organization_id);
