package store

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	defaultPageSize int32 = 50
	maxPageSize     int32 = 100
)

var (
	ErrSecretProviderNotFound = errors.New("secret provider not found")
	ErrSecretNotFound         = errors.New("secret not found")
	ErrInvalidPageToken       = errors.New("invalid page token")
)

type ProviderType string

const (
	ProviderTypeVault ProviderType = "vault"
)

type SecretProvider struct {
	ID          uuid.UUID
	TenantID    uuid.UUID
	Title       string
	Description string
	Type        ProviderType
	Config      json.RawMessage
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type Secret struct {
	ID               uuid.UUID
	TenantID         uuid.UUID
	Title            string
	Description      string
	SecretProviderID uuid.UUID
	RemoteName       string
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

type Store struct {
	pool *pgxpool.Pool
}

func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

type CreateSecretProviderInput struct {
	TenantID    uuid.UUID
	Title       string
	Description string
	Type        ProviderType
	Config      json.RawMessage
}

type UpdateSecretProviderInput struct {
	Title       *string
	Description *string
	Type        *ProviderType
	Config      *json.RawMessage
}

type ListSecretProvidersParams struct {
	TenantID  uuid.UUID
	PageSize  int32
	PageToken string
}

func (s *Store) CreateSecretProvider(ctx context.Context, input CreateSecretProviderInput) (SecretProvider, error) {
	row := s.pool.QueryRow(ctx, `
		INSERT INTO secret_providers (tenant_id, title, description, type, config)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, tenant_id, title, description, type, config, created_at, updated_at
	`, input.TenantID, input.Title, input.Description, input.Type, input.Config)
	return scanSecretProvider(row)
}

func (s *Store) GetSecretProvider(ctx context.Context, tenantID uuid.UUID, id uuid.UUID) (SecretProvider, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT id, tenant_id, title, description, type, config, created_at, updated_at
		FROM secret_providers
		WHERE tenant_id = $1 AND id = $2
	`, tenantID, id)
	return scanSecretProvider(row)
}

func (s *Store) UpdateSecretProvider(ctx context.Context, tenantID uuid.UUID, id uuid.UUID, input UpdateSecretProviderInput) (SecretProvider, error) {
	row := s.pool.QueryRow(ctx, `
		UPDATE secret_providers
		SET title = COALESCE($3, title),
			description = COALESCE($4, description),
			type = COALESCE($5, type),
			config = COALESCE($6, config),
			updated_at = NOW()
		WHERE tenant_id = $1 AND id = $2
		RETURNING id, tenant_id, title, description, type, config, created_at, updated_at
	`, tenantID, id, input.Title, input.Description, input.Type, input.Config)
	return scanSecretProvider(row)
}

func (s *Store) DeleteSecretProvider(ctx context.Context, tenantID uuid.UUID, id uuid.UUID) error {
	var deletedID uuid.UUID
	if err := s.pool.QueryRow(ctx, `DELETE FROM secret_providers WHERE tenant_id = $1 AND id = $2 RETURNING id`, tenantID, id).Scan(&deletedID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrSecretProviderNotFound
		}
		return err
	}
	return nil
}

func (s *Store) ListSecretProviders(ctx context.Context, params ListSecretProvidersParams) ([]SecretProvider, string, error) {
	page, err := newPageParams(params.PageSize, params.PageToken)
	if err != nil {
		return nil, "", err
	}

	stmt := "SELECT id, tenant_id, title, description, type, config, created_at, updated_at FROM secret_providers"
	stmt += " WHERE tenant_id = $1 ORDER BY created_at DESC, id DESC LIMIT $2 OFFSET $3"
	args := []any{params.TenantID, page.Limit + 1, page.Offset}

	rows, err := s.pool.Query(ctx, stmt, args...)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()

	providers := make([]SecretProvider, 0, int(page.Limit))
	for rows.Next() {
		provider, err := scanSecretProvider(rows)
		if err != nil {
			return nil, "", err
		}
		providers = append(providers, provider)
	}
	if rows.Err() != nil {
		return nil, "", rows.Err()
	}

	providers, nextToken, err := finalizePage(providers, page)
	if err != nil {
		return nil, "", err
	}

	return providers, nextToken, nil
}

type CreateSecretInput struct {
	TenantID         uuid.UUID
	Title            string
	Description      string
	SecretProviderID uuid.UUID
	RemoteName       string
}

type UpdateSecretInput struct {
	Title            *string
	Description      *string
	SecretProviderID *uuid.UUID
	RemoteName       *string
}

type ListSecretsParams struct {
	TenantID         uuid.UUID
	PageSize         int32
	PageToken        string
	SecretProviderID *uuid.UUID
}

func (s *Store) CreateSecret(ctx context.Context, input CreateSecretInput) (Secret, error) {
	row := s.pool.QueryRow(ctx, `
		INSERT INTO secrets (tenant_id, title, description, secret_provider_id, remote_name)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, tenant_id, title, description, secret_provider_id, remote_name, created_at, updated_at
	`, input.TenantID, input.Title, input.Description, input.SecretProviderID, input.RemoteName)
	return scanSecret(row)
}

func (s *Store) GetSecret(ctx context.Context, tenantID uuid.UUID, id uuid.UUID) (Secret, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT id, tenant_id, title, description, secret_provider_id, remote_name, created_at, updated_at
		FROM secrets
		WHERE tenant_id = $1 AND id = $2
	`, tenantID, id)
	return scanSecret(row)
}

func (s *Store) UpdateSecret(ctx context.Context, tenantID uuid.UUID, id uuid.UUID, input UpdateSecretInput) (Secret, error) {
	row := s.pool.QueryRow(ctx, `
		UPDATE secrets
		SET title = COALESCE($3, title),
			description = COALESCE($4, description),
			secret_provider_id = COALESCE($5, secret_provider_id),
			remote_name = COALESCE($6, remote_name),
			updated_at = NOW()
		WHERE tenant_id = $1 AND id = $2
		RETURNING id, tenant_id, title, description, secret_provider_id, remote_name, created_at, updated_at
	`, tenantID, id, input.Title, input.Description, input.SecretProviderID, input.RemoteName)
	return scanSecret(row)
}

func (s *Store) DeleteSecret(ctx context.Context, tenantID uuid.UUID, id uuid.UUID) error {
	var deletedID uuid.UUID
	if err := s.pool.QueryRow(ctx, `DELETE FROM secrets WHERE tenant_id = $1 AND id = $2 RETURNING id`, tenantID, id).Scan(&deletedID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrSecretNotFound
		}
		return err
	}
	return nil
}

func (s *Store) ListSecrets(ctx context.Context, params ListSecretsParams) ([]Secret, string, error) {
	page, err := newPageParams(params.PageSize, params.PageToken)
	if err != nil {
		return nil, "", err
	}

	conditions := []string{"tenant_id = $1"}
	args := []any{params.TenantID}
	if params.SecretProviderID != nil {
		args = append(args, *params.SecretProviderID)
		conditions = append(conditions, fmt.Sprintf("secret_provider_id = $%d", len(args)))
	}

	stmt := `SELECT id, tenant_id, title, description, secret_provider_id, remote_name, created_at, updated_at FROM secrets`
	stmt += " WHERE " + strings.Join(conditions, " AND ")
	limitStart := len(args)
	args = append(args, page.Limit+1, page.Offset)
	stmt += fmt.Sprintf(" ORDER BY created_at DESC, id DESC LIMIT $%d OFFSET $%d", limitStart+1, limitStart+2)

	rows, err := s.pool.Query(ctx, stmt, args...)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()

	secrets := make([]Secret, 0, int(page.Limit))
	for rows.Next() {
		secret, err := scanSecret(rows)
		if err != nil {
			return nil, "", err
		}
		secrets = append(secrets, secret)
	}
	if rows.Err() != nil {
		return nil, "", rows.Err()
	}

	secrets, nextToken, err := finalizePage(secrets, page)
	if err != nil {
		return nil, "", err
	}

	return secrets, nextToken, nil
}

func scanSecretProvider(row pgx.Row) (SecretProvider, error) {
	var provider SecretProvider
	if err := row.Scan(&provider.ID, &provider.TenantID, &provider.Title, &provider.Description, &provider.Type, &provider.Config, &provider.CreatedAt, &provider.UpdatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return SecretProvider{}, ErrSecretProviderNotFound
		}
		return SecretProvider{}, err
	}
	return provider, nil
}

func scanSecret(row pgx.Row) (Secret, error) {
	var secret Secret
	if err := row.Scan(&secret.ID, &secret.TenantID, &secret.Title, &secret.Description, &secret.SecretProviderID, &secret.RemoteName, &secret.CreatedAt, &secret.UpdatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Secret{}, ErrSecretNotFound
		}
		return Secret{}, err
	}
	return secret, nil
}

type pageParams struct {
	Limit  int32
	Offset int64
}

func newPageParams(pageSize int32, pageToken string) (pageParams, error) {
	limit := NormalizePageSize(pageSize)
	offset := int64(0)
	if pageToken != "" {
		var err error
		offset, err = DecodePageToken(pageToken)
		if err != nil {
			return pageParams{}, err
		}
	}
	return pageParams{Limit: limit, Offset: offset}, nil
}

func finalizePage[T any](items []T, params pageParams) ([]T, string, error) {
	if len(items) <= int(params.Limit) {
		return items, "", nil
	}

	nextToken, err := EncodePageToken(params.Offset + int64(params.Limit))
	if err != nil {
		return nil, "", err
	}

	return items[:params.Limit], nextToken, nil
}

type pageToken struct {
	Offset int64 `json:"offset"`
}

func EncodePageToken(offset int64) (string, error) {
	payload := pageToken{Offset: offset}
	buf, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func DecodePageToken(token string) (int64, error) {
	if token == "" {
		return 0, ErrInvalidPageToken
	}
	data, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return 0, fmt.Errorf("%w: decode token: %v", ErrInvalidPageToken, err)
	}
	var payload pageToken
	if err := json.Unmarshal(data, &payload); err != nil {
		return 0, fmt.Errorf("%w: unmarshal token: %v", ErrInvalidPageToken, err)
	}
	if payload.Offset < 0 {
		return 0, ErrInvalidPageToken
	}
	return payload.Offset, nil
}

func NormalizePageSize(size int32) int32 {
	if size <= 0 {
		return defaultPageSize
	}
	if size > maxPageSize {
		return maxPageSize
	}
	return size
}
