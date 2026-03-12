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
	Title       string
	Description string
	Type        ProviderType
	Config      json.RawMessage
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type Secret struct {
	ID               uuid.UUID
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

type SecretProviderListResult struct {
	SecretProviders []SecretProvider
	NextPageToken   string
}

func (s *Store) CreateSecretProvider(ctx context.Context, input CreateSecretProviderInput) (SecretProvider, error) {
	row := s.pool.QueryRow(ctx, `
        INSERT INTO secret_providers (title, description, type, config)
        VALUES ($1, $2, $3, $4)
        RETURNING id, title, description, type, config, created_at, updated_at
    `, input.Title, input.Description, input.Type, input.Config)
	return scanSecretProvider(row)
}

func (s *Store) GetSecretProvider(ctx context.Context, id uuid.UUID) (SecretProvider, error) {
	row := s.pool.QueryRow(ctx, `
        SELECT id, title, description, type, config, created_at, updated_at
        FROM secret_providers
        WHERE id = $1
    `, id)
	return scanSecretProvider(row)
}

func (s *Store) UpdateSecretProvider(ctx context.Context, id uuid.UUID, input UpdateSecretProviderInput) (SecretProvider, error) {
	row := s.pool.QueryRow(ctx, `
        UPDATE secret_providers
        SET title = COALESCE($2, title),
            description = COALESCE($3, description),
            type = COALESCE($4, type),
            config = COALESCE($5, config),
            updated_at = NOW()
        WHERE id = $1
        RETURNING id, title, description, type, config, created_at, updated_at
    `, id, input.Title, input.Description, input.Type, input.Config)
	return scanSecretProvider(row)
}

func (s *Store) DeleteSecretProvider(ctx context.Context, id uuid.UUID) error {
	var deletedID uuid.UUID
	if err := s.pool.QueryRow(ctx, `DELETE FROM secret_providers WHERE id = $1 RETURNING id`, id).Scan(&deletedID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrSecretProviderNotFound
		}
		return err
	}
	return nil
}

func (s *Store) ListSecretProviders(ctx context.Context, pageSize int32, pageToken, query string) (SecretProviderListResult, error) {
	limit := normalizePageSize(pageSize)
	offset := int64(0)
	if pageToken != "" {
		var err error
		offset, err = decodePageToken(pageToken)
		if err != nil {
			return SecretProviderListResult{}, err
		}
	}

	conditions := make([]string, 0, 1)
	args := make([]any, 0, 4)
	if query != "" {
		pattern := "%" + query + "%"
		start := len(args)
		args = append(args, pattern, pattern)
		conditions = append(conditions, fmt.Sprintf("(title ILIKE $%d OR description ILIKE $%d)", start+1, start+2))
	}

	stmt := `SELECT id, title, description, type, config, created_at, updated_at FROM secret_providers`
	if len(conditions) > 0 {
		stmt += " WHERE " + strings.Join(conditions, " AND ")
	}
	limitStart := len(args)
	args = append(args, limit+1, offset)
	stmt += fmt.Sprintf(" ORDER BY created_at DESC, id DESC LIMIT $%d OFFSET $%d", limitStart+1, limitStart+2)

	rows, err := s.pool.Query(ctx, stmt, args...)
	if err != nil {
		return SecretProviderListResult{}, err
	}
	defer rows.Close()

	providers := make([]SecretProvider, 0, limit)
	for rows.Next() {
		provider, err := scanSecretProvider(rows)
		if err != nil {
			return SecretProviderListResult{}, err
		}
		providers = append(providers, provider)
	}
	if rows.Err() != nil {
		return SecretProviderListResult{}, rows.Err()
	}

	nextToken := ""
	if len(providers) > int(limit) {
		providers = providers[:limit]
		nextToken, err = encodePageToken(offset + int64(limit))
		if err != nil {
			return SecretProviderListResult{}, err
		}
	}

	return SecretProviderListResult{SecretProviders: providers, NextPageToken: nextToken}, nil
}

type CreateSecretInput struct {
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

type SecretListResult struct {
	Secrets       []Secret
	NextPageToken string
}

func (s *Store) CreateSecret(ctx context.Context, input CreateSecretInput) (Secret, error) {
	row := s.pool.QueryRow(ctx, `
        INSERT INTO secrets (title, description, secret_provider_id, remote_name)
        VALUES ($1, $2, $3, $4)
        RETURNING id, title, description, secret_provider_id, remote_name, created_at, updated_at
    `, input.Title, input.Description, input.SecretProviderID, input.RemoteName)
	return scanSecret(row)
}

func (s *Store) GetSecret(ctx context.Context, id uuid.UUID) (Secret, error) {
	row := s.pool.QueryRow(ctx, `
        SELECT id, title, description, secret_provider_id, remote_name, created_at, updated_at
        FROM secrets
        WHERE id = $1
    `, id)
	return scanSecret(row)
}

func (s *Store) UpdateSecret(ctx context.Context, id uuid.UUID, input UpdateSecretInput) (Secret, error) {
	row := s.pool.QueryRow(ctx, `
        UPDATE secrets
        SET title = COALESCE($2, title),
            description = COALESCE($3, description),
            secret_provider_id = COALESCE($4, secret_provider_id),
            remote_name = COALESCE($5, remote_name),
            updated_at = NOW()
        WHERE id = $1
        RETURNING id, title, description, secret_provider_id, remote_name, created_at, updated_at
    `, id, input.Title, input.Description, input.SecretProviderID, input.RemoteName)
	return scanSecret(row)
}

func (s *Store) DeleteSecret(ctx context.Context, id uuid.UUID) error {
	var deletedID uuid.UUID
	if err := s.pool.QueryRow(ctx, `DELETE FROM secrets WHERE id = $1 RETURNING id`, id).Scan(&deletedID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrSecretNotFound
		}
		return err
	}
	return nil
}

func (s *Store) ListSecrets(ctx context.Context, pageSize int32, pageToken, query string) (SecretListResult, error) {
	limit := normalizePageSize(pageSize)
	offset := int64(0)
	if pageToken != "" {
		var err error
		offset, err = decodePageToken(pageToken)
		if err != nil {
			return SecretListResult{}, err
		}
	}

	conditions := make([]string, 0, 1)
	args := make([]any, 0, 4)
	if query != "" {
		pattern := "%" + query + "%"
		start := len(args)
		args = append(args, pattern, pattern)
		conditions = append(conditions, fmt.Sprintf("(title ILIKE $%d OR description ILIKE $%d)", start+1, start+2))
	}

	stmt := `SELECT id, title, description, secret_provider_id, remote_name, created_at, updated_at FROM secrets`
	if len(conditions) > 0 {
		stmt += " WHERE " + strings.Join(conditions, " AND ")
	}
	limitStart := len(args)
	args = append(args, limit+1, offset)
	stmt += fmt.Sprintf(" ORDER BY created_at DESC, id DESC LIMIT $%d OFFSET $%d", limitStart+1, limitStart+2)

	rows, err := s.pool.Query(ctx, stmt, args...)
	if err != nil {
		return SecretListResult{}, err
	}
	defer rows.Close()

	secrets := make([]Secret, 0, limit)
	for rows.Next() {
		secret, err := scanSecret(rows)
		if err != nil {
			return SecretListResult{}, err
		}
		secrets = append(secrets, secret)
	}
	if rows.Err() != nil {
		return SecretListResult{}, rows.Err()
	}

	nextToken := ""
	if len(secrets) > int(limit) {
		secrets = secrets[:limit]
		nextToken, err = encodePageToken(offset + int64(limit))
		if err != nil {
			return SecretListResult{}, err
		}
	}

	return SecretListResult{Secrets: secrets, NextPageToken: nextToken}, nil
}

func scanSecretProvider(row pgx.Row) (SecretProvider, error) {
	var provider SecretProvider
	if err := row.Scan(&provider.ID, &provider.Title, &provider.Description, &provider.Type, &provider.Config, &provider.CreatedAt, &provider.UpdatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return SecretProvider{}, ErrSecretProviderNotFound
		}
		return SecretProvider{}, err
	}
	return provider, nil
}

func scanSecret(row pgx.Row) (Secret, error) {
	var secret Secret
	if err := row.Scan(&secret.ID, &secret.Title, &secret.Description, &secret.SecretProviderID, &secret.RemoteName, &secret.CreatedAt, &secret.UpdatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Secret{}, ErrSecretNotFound
		}
		return Secret{}, err
	}
	return secret, nil
}

type pageToken struct {
	Offset int64 `json:"offset"`
}

func encodePageToken(offset int64) (string, error) {
	payload := pageToken{Offset: offset}
	buf, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func decodePageToken(token string) (int64, error) {
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

func normalizePageSize(size int32) int32 {
	if size <= 0 {
		return defaultPageSize
	}
	if size > maxPageSize {
		return maxPageSize
	}
	return size
}
