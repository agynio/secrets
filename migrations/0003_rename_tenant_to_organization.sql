ALTER TABLE secret_providers
    RENAME COLUMN tenant_id TO organization_id;

ALTER TABLE secrets
    RENAME COLUMN tenant_id TO organization_id;

ALTER INDEX idx_secret_providers_tenant_id
    RENAME TO idx_secret_providers_organization_id;

ALTER INDEX idx_secrets_tenant_id
    RENAME TO idx_secrets_organization_id;

ALTER INDEX idx_secrets_tenant_provider
    RENAME TO idx_secrets_organization_provider;
