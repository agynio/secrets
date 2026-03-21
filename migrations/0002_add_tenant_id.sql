ALTER TABLE secret_providers
    ADD COLUMN tenant_id UUID NOT NULL;

ALTER TABLE secrets
    ADD COLUMN tenant_id UUID NOT NULL;

CREATE INDEX idx_secret_providers_tenant_id ON secret_providers (tenant_id);
CREATE INDEX idx_secrets_tenant_id ON secrets (tenant_id);
CREATE INDEX idx_secrets_tenant_provider ON secrets (tenant_id, secret_provider_id);
