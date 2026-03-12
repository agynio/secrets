package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	secretsv1 "github.com/agynio/secrets/gen/go/agynio/api/secrets/v1"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/agynio/secrets/internal/store"
)

type SecretStore interface {
	CreateSecretProvider(ctx context.Context, input store.CreateSecretProviderInput) (store.SecretProvider, error)
	GetSecretProvider(ctx context.Context, id uuid.UUID) (store.SecretProvider, error)
	UpdateSecretProvider(ctx context.Context, id uuid.UUID, input store.UpdateSecretProviderInput) (store.SecretProvider, error)
	DeleteSecretProvider(ctx context.Context, id uuid.UUID) error
	ListSecretProviders(ctx context.Context, params store.ListSecretProvidersParams) ([]store.SecretProvider, string, error)
	CreateSecret(ctx context.Context, input store.CreateSecretInput) (store.Secret, error)
	GetSecret(ctx context.Context, id uuid.UUID) (store.Secret, error)
	UpdateSecret(ctx context.Context, id uuid.UUID, input store.UpdateSecretInput) (store.Secret, error)
	DeleteSecret(ctx context.Context, id uuid.UUID) error
	ListSecrets(ctx context.Context, params store.ListSecretsParams) ([]store.Secret, string, error)
}

type VaultResolver interface {
	ReadKV2(ctx context.Context, address, token, mount, path, key string) (string, error)
}

type Server struct {
	secretsv1.UnimplementedSecretsServiceServer
	store SecretStore
	vault VaultResolver
}

func New(store SecretStore, vaultClient VaultResolver) *Server {
	return &Server{store: store, vault: vaultClient}
}

func (s *Server) CreateSecretProvider(ctx context.Context, req *secretsv1.CreateSecretProviderRequest) (*secretsv1.CreateSecretProviderResponse, error) {
	providerType, err := providerTypeFromProto(req.GetType())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "type: %v", err)
	}
	config, err := configFromProto(providerType, req.GetConfig())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "config: %v", err)
	}

	provider, err := s.store.CreateSecretProvider(ctx, store.CreateSecretProviderInput{
		Title:       req.GetTitle(),
		Description: req.GetDescription(),
		Type:        providerType,
		Config:      config,
	})
	if err != nil {
		return nil, toStatusError(err)
	}
	protoProvider, err := toProtoSecretProvider(provider)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "convert secret provider: %v", err)
	}
	return &secretsv1.CreateSecretProviderResponse{SecretProvider: protoProvider}, nil
}

func (s *Server) GetSecretProvider(ctx context.Context, req *secretsv1.GetSecretProviderRequest) (*secretsv1.GetSecretProviderResponse, error) {
	providerID, err := parseUUID(req.GetId())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "id: %v", err)
	}
	provider, err := s.store.GetSecretProvider(ctx, providerID)
	if err != nil {
		return nil, toStatusError(err)
	}
	protoProvider, err := toProtoSecretProvider(provider)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "convert secret provider: %v", err)
	}
	return &secretsv1.GetSecretProviderResponse{SecretProvider: protoProvider}, nil
}

func (s *Server) UpdateSecretProvider(ctx context.Context, req *secretsv1.UpdateSecretProviderRequest) (*secretsv1.UpdateSecretProviderResponse, error) {
	providerID, err := parseUUID(req.GetId())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "id: %v", err)
	}

	existing, err := s.store.GetSecretProvider(ctx, providerID)
	if err != nil {
		return nil, toStatusError(err)
	}

	var configUpdate *json.RawMessage
	if req.Config != nil {
		config, err := configFromProto(existing.Type, req.GetConfig())
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "config: %v", err)
		}
		configUpdate = &config
	}

	provider, err := s.store.UpdateSecretProvider(ctx, providerID, store.UpdateSecretProviderInput{
		Title:       req.Title,
		Description: req.Description,
		Type:        nil,
		Config:      configUpdate,
	})
	if err != nil {
		return nil, toStatusError(err)
	}
	protoProvider, err := toProtoSecretProvider(provider)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "convert secret provider: %v", err)
	}
	return &secretsv1.UpdateSecretProviderResponse{SecretProvider: protoProvider}, nil
}

func (s *Server) DeleteSecretProvider(ctx context.Context, req *secretsv1.DeleteSecretProviderRequest) (*secretsv1.DeleteSecretProviderResponse, error) {
	providerID, err := parseUUID(req.GetId())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "id: %v", err)
	}
	if err := s.store.DeleteSecretProvider(ctx, providerID); err != nil {
		return nil, toStatusError(err)
	}
	return &secretsv1.DeleteSecretProviderResponse{}, nil
}

func (s *Server) ListSecretProviders(ctx context.Context, req *secretsv1.ListSecretProvidersRequest) (*secretsv1.ListSecretProvidersResponse, error) {
	providers, nextToken, err := s.store.ListSecretProviders(ctx, store.ListSecretProvidersParams{
		PageSize:  req.GetPageSize(),
		PageToken: req.GetPageToken(),
		Query:     req.GetQuery(),
	})
	if err != nil {
		return nil, toStatusError(err)
	}

	resp := &secretsv1.ListSecretProvidersResponse{
		SecretProviders: make([]*secretsv1.SecretProvider, len(providers)),
		NextPageToken:   nextToken,
	}
	for i, provider := range providers {
		protoProvider, err := toProtoSecretProvider(provider)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "convert secret provider: %v", err)
		}
		resp.SecretProviders[i] = protoProvider
	}
	return resp, nil
}

func (s *Server) CreateSecret(ctx context.Context, req *secretsv1.CreateSecretRequest) (*secretsv1.CreateSecretResponse, error) {
	providerID, err := parseUUID(req.GetSecretProviderId())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "secret_provider_id: %v", err)
	}
	if req.GetRemoteName() == "" {
		return nil, status.Error(codes.InvalidArgument, "remote_name must be provided")
	}
	secret, err := s.store.CreateSecret(ctx, store.CreateSecretInput{
		Title:            req.GetTitle(),
		Description:      req.GetDescription(),
		SecretProviderID: providerID,
		RemoteName:       req.GetRemoteName(),
	})
	if err != nil {
		return nil, toStatusError(err)
	}
	protoSecret := toProtoSecret(secret)
	return &secretsv1.CreateSecretResponse{Secret: protoSecret}, nil
}

func (s *Server) GetSecret(ctx context.Context, req *secretsv1.GetSecretRequest) (*secretsv1.GetSecretResponse, error) {
	secretID, err := parseUUID(req.GetId())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "id: %v", err)
	}
	secret, err := s.store.GetSecret(ctx, secretID)
	if err != nil {
		return nil, toStatusError(err)
	}
	return &secretsv1.GetSecretResponse{Secret: toProtoSecret(secret)}, nil
}

func (s *Server) UpdateSecret(ctx context.Context, req *secretsv1.UpdateSecretRequest) (*secretsv1.UpdateSecretResponse, error) {
	secretID, err := parseUUID(req.GetId())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "id: %v", err)
	}

	var providerID *uuid.UUID
	if req.SecretProviderId != nil {
		parsed, err := parseUUID(req.GetSecretProviderId())
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "secret_provider_id: %v", err)
		}
		providerID = &parsed
	}

	var remoteName *string
	if req.RemoteName != nil {
		if req.GetRemoteName() == "" {
			return nil, status.Error(codes.InvalidArgument, "remote_name must be provided")
		}
		value := req.GetRemoteName()
		remoteName = &value
	}

	secret, err := s.store.UpdateSecret(ctx, secretID, store.UpdateSecretInput{
		Title:            req.Title,
		Description:      req.Description,
		SecretProviderID: providerID,
		RemoteName:       remoteName,
	})
	if err != nil {
		return nil, toStatusError(err)
	}
	return &secretsv1.UpdateSecretResponse{Secret: toProtoSecret(secret)}, nil
}

func (s *Server) DeleteSecret(ctx context.Context, req *secretsv1.DeleteSecretRequest) (*secretsv1.DeleteSecretResponse, error) {
	secretID, err := parseUUID(req.GetId())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "id: %v", err)
	}
	if err := s.store.DeleteSecret(ctx, secretID); err != nil {
		return nil, toStatusError(err)
	}
	return &secretsv1.DeleteSecretResponse{}, nil
}

func (s *Server) ListSecrets(ctx context.Context, req *secretsv1.ListSecretsRequest) (*secretsv1.ListSecretsResponse, error) {
	params := store.ListSecretsParams{
		PageSize:  req.GetPageSize(),
		PageToken: req.GetPageToken(),
		Query:     req.GetQuery(),
	}
	if req.GetSecretProviderId() != "" {
		providerID, err := parseUUID(req.GetSecretProviderId())
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "secret_provider_id: %v", err)
		}
		params.SecretProviderID = &providerID
	}

	secrets, nextToken, err := s.store.ListSecrets(ctx, params)
	if err != nil {
		return nil, toStatusError(err)
	}

	resp := &secretsv1.ListSecretsResponse{
		Secrets:       make([]*secretsv1.Secret, len(secrets)),
		NextPageToken: nextToken,
	}
	for i, secret := range secrets {
		resp.Secrets[i] = toProtoSecret(secret)
	}
	return resp, nil
}

func (s *Server) ResolveSecret(ctx context.Context, req *secretsv1.ResolveSecretRequest) (*secretsv1.ResolveSecretResponse, error) {
	secretID, err := parseUUID(req.GetId())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "id: %v", err)
	}
	secret, err := s.store.GetSecret(ctx, secretID)
	if err != nil {
		return nil, toStatusError(err)
	}
	provider, err := s.store.GetSecretProvider(ctx, secret.SecretProviderID)
	if err != nil {
		return nil, toStatusError(err)
	}
	if provider.Type != store.ProviderTypeVault {
		return nil, status.Errorf(codes.FailedPrecondition, "unsupported secret provider type: %s", provider.Type)
	}
	config, err := vaultConfigFromJSON(provider.Config)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "decode secret provider config: %v", err)
	}
	ref, err := parseVaultRemoteName(secret.RemoteName)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "remote_name: %v", err)
	}
	value, err := s.vault.ReadKV2(ctx, config.Address, config.Token, ref.Mount, ref.Path, ref.Key)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "resolve vault secret: %v", err)
	}
	return &secretsv1.ResolveSecretResponse{Value: value}, nil
}

type vaultConfig struct {
	Address string `json:"address"`
	Token   string `json:"token"`
}

func configFromProto(providerType store.ProviderType, config *secretsv1.SecretProviderConfig) (json.RawMessage, error) {
	switch providerType {
	case store.ProviderTypeVault:
		vaultCfg, err := vaultConfigFromProto(config)
		if err != nil {
			return nil, err
		}
		payload, err := json.Marshal(vaultCfg)
		if err != nil {
			return nil, err
		}
		return payload, nil
	default:
		return nil, fmt.Errorf("unknown provider type %q", providerType)
	}
}

func vaultConfigFromProto(config *secretsv1.SecretProviderConfig) (vaultConfig, error) {
	if config == nil {
		return vaultConfig{}, fmt.Errorf("config must be provided")
	}
	switch cfg := config.GetProvider().(type) {
	case *secretsv1.SecretProviderConfig_Vault:
		if cfg.Vault == nil {
			return vaultConfig{}, fmt.Errorf("vault config must be provided")
		}
		address := strings.TrimSpace(cfg.Vault.GetAddress())
		if address == "" {
			return vaultConfig{}, fmt.Errorf("vault.address must be provided")
		}
		token := strings.TrimSpace(cfg.Vault.GetToken())
		if token == "" {
			return vaultConfig{}, fmt.Errorf("vault.token must be provided")
		}
		return vaultConfig{Address: address, Token: token}, nil
	default:
		return vaultConfig{}, fmt.Errorf("unsupported config type")
	}
}

func vaultConfigFromJSON(raw json.RawMessage) (vaultConfig, error) {
	var cfg vaultConfig
	// TODO: encrypt sensitive vault config fields at rest.
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return vaultConfig{}, err
	}
	return cfg, nil
}

func toProtoSecretProvider(provider store.SecretProvider) (*secretsv1.SecretProvider, error) {
	providerType, err := providerTypeToProto(provider.Type)
	if err != nil {
		return nil, err
	}
	config, err := configToProto(provider.Type, provider.Config)
	if err != nil {
		return nil, err
	}
	return &secretsv1.SecretProvider{
		Meta:        toProtoEntityMeta(provider.ID, provider.CreatedAt, provider.UpdatedAt),
		Title:       provider.Title,
		Description: provider.Description,
		Type:        providerType,
		Config:      config,
	}, nil
}

func toProtoSecret(secret store.Secret) *secretsv1.Secret {
	return &secretsv1.Secret{
		Meta:             toProtoEntityMeta(secret.ID, secret.CreatedAt, secret.UpdatedAt),
		Title:            secret.Title,
		Description:      secret.Description,
		SecretProviderId: secret.SecretProviderID.String(),
		RemoteName:       secret.RemoteName,
	}
}

func toProtoEntityMeta(id uuid.UUID, createdAt, updatedAt time.Time) *secretsv1.EntityMeta {
	return &secretsv1.EntityMeta{
		Id:        id.String(),
		CreatedAt: timestamppb.New(createdAt),
		UpdatedAt: timestamppb.New(updatedAt),
	}
}

func configToProto(providerType store.ProviderType, raw json.RawMessage) (*secretsv1.SecretProviderConfig, error) {
	switch providerType {
	case store.ProviderTypeVault:
		cfg, err := vaultConfigFromJSON(raw)
		if err != nil {
			return nil, err
		}
		return &secretsv1.SecretProviderConfig{
			Provider: &secretsv1.SecretProviderConfig_Vault{
				Vault: &secretsv1.VaultConfig{
					Address: cfg.Address,
					Token:   cfg.Token,
				},
			},
		}, nil
	default:
		return nil, fmt.Errorf("unknown provider type %q", providerType)
	}
}

func providerTypeFromProto(value secretsv1.SecretProviderType) (store.ProviderType, error) {
	switch value {
	case secretsv1.SecretProviderType_SECRET_PROVIDER_TYPE_UNSPECIFIED:
		return "", fmt.Errorf("provider type must be specified")
	case secretsv1.SecretProviderType_SECRET_PROVIDER_TYPE_VAULT:
		return store.ProviderTypeVault, nil
	default:
		return "", fmt.Errorf("unknown provider type %v", value)
	}
}

func providerTypeToProto(value store.ProviderType) (secretsv1.SecretProviderType, error) {
	switch value {
	case store.ProviderTypeVault:
		return secretsv1.SecretProviderType_SECRET_PROVIDER_TYPE_VAULT, nil
	default:
		return secretsv1.SecretProviderType_SECRET_PROVIDER_TYPE_UNSPECIFIED, fmt.Errorf("unknown provider type %q", value)
	}
}

type vaultRemoteRef struct {
	Mount string
	Path  string
	Key   string
}

func parseVaultRemoteName(remoteName string) (vaultRemoteRef, error) {
	parts := strings.Split(remoteName, "/")
	if len(parts) < 3 {
		return vaultRemoteRef{}, fmt.Errorf("remote_name must be <mount>/<path>/<key>")
	}
	for _, part := range parts {
		if part == "" {
			return vaultRemoteRef{}, fmt.Errorf("remote_name segments must be non-empty")
		}
	}
	mount := parts[0]
	key := parts[len(parts)-1]
	path := strings.Join(parts[1:len(parts)-1], "/")
	return vaultRemoteRef{Mount: mount, Path: path, Key: key}, nil
}

func parseUUID(value string) (uuid.UUID, error) {
	if value == "" {
		return uuid.UUID{}, fmt.Errorf("value is empty")
	}
	id, err := uuid.Parse(value)
	if err != nil {
		return uuid.UUID{}, err
	}
	return id, nil
}

func toStatusError(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23503" {
		return status.Error(codes.FailedPrecondition, pgErr.Message)
	}
	switch {
	case errors.Is(err, store.ErrSecretProviderNotFound), errors.Is(err, store.ErrSecretNotFound):
		return status.Error(codes.NotFound, err.Error())
	case errors.Is(err, store.ErrInvalidPageToken):
		return status.Error(codes.InvalidArgument, err.Error())
	default:
		return status.Errorf(codes.Internal, "internal error: %v", err)
	}
}
