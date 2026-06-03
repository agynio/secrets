package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	secretsv1 "github.com/agynio/secrets/gen/go/agynio/api/secrets/v1"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/agynio/secrets/internal/crypto"
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
	CreateImagePullSecret(ctx context.Context, input store.CreateImagePullSecretInput) (store.ImagePullSecret, error)
	GetImagePullSecret(ctx context.Context, id uuid.UUID) (store.ImagePullSecret, error)
	UpdateImagePullSecret(ctx context.Context, id uuid.UUID, input store.UpdateImagePullSecretInput) (store.ImagePullSecret, error)
	DeleteImagePullSecret(ctx context.Context, id uuid.UUID) error
	ListImagePullSecrets(ctx context.Context, params store.ListImagePullSecretsParams) ([]store.ImagePullSecret, string, error)
}

type VaultResolver interface {
	ReadKV2(ctx context.Context, address, token, mount, path, key string) (string, error)
}

type Server struct {
	secretsv1.UnimplementedSecretsServiceServer
	store         SecretStore
	vault         VaultResolver
	egressRules   EgressRulesClient
	encryptionKey []byte
}

func New(store SecretStore, vaultClient VaultResolver, encryptionKey []byte) *Server {
	return &Server{store: store, vault: vaultClient, encryptionKey: encryptionKey}
}

func (s *Server) WithEgressRulesClient(client EgressRulesClient) *Server {
	s.egressRules = client
	return s
}

func (s *Server) CreateSecretProvider(ctx context.Context, req *secretsv1.CreateSecretProviderRequest) (*secretsv1.CreateSecretProviderResponse, error) {
	organizationID, err := parseUUID(req.GetOrganizationId())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "organization_id: %v", err)
	}

	providerType, err := providerTypeFromProto(req.GetType())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "type: %v", err)
	}
	config, err := configFromProto(providerType, req.GetConfig())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "config: %v", err)
	}

	provider, err := s.store.CreateSecretProvider(ctx, store.CreateSecretProviderInput{
		OrganizationID: organizationID,
		Title:          req.GetTitle(),
		Description:    req.GetDescription(),
		Type:           providerType,
		Config:         config,
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
	organizationID, err := parseUUID(req.GetOrganizationId())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "organization_id: %v", err)
	}

	providers, nextToken, err := s.store.ListSecretProviders(ctx, store.ListSecretProvidersParams{
		OrganizationID: organizationID,
		PageSize:       req.GetPageSize(),
		PageToken:      req.GetPageToken(),
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
	organizationID, err := parseUUID(req.GetOrganizationId())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "organization_id: %v", err)
	}

	value := req.GetValue()
	var providerID *uuid.UUID
	remoteName := ""
	var encryptedValue []byte
	if value != "" {
		if req.GetSecretProviderId() != "" || req.GetRemoteName() != "" {
			return nil, status.Error(codes.InvalidArgument, "value is mutually exclusive with secret_provider_id and remote_name")
		}
		var err error
		encryptedValue, err = crypto.Encrypt(s.encryptionKey, []byte(value))
		if err != nil {
			return nil, status.Errorf(codes.Internal, "encrypt value: %v", err)
		}
	} else {
		parsed, err := parseUUID(req.GetSecretProviderId())
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "secret_provider_id: %v", err)
		}
		trimmedRemoteName := strings.TrimSpace(req.GetRemoteName())
		if trimmedRemoteName == "" {
			return nil, status.Error(codes.InvalidArgument, "remote_name must be provided")
		}
		providerID = &parsed
		remoteName = trimmedRemoteName
	}
	secret, err := s.store.CreateSecret(ctx, store.CreateSecretInput{
		OrganizationID:   organizationID,
		Title:            req.GetTitle(),
		Description:      req.GetDescription(),
		SecretProviderID: providerID,
		RemoteName:       remoteName,
		EncryptedValue:   encryptedValue,
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
	var remoteName *string
	var encryptedValue *[]byte
	setProviderID := false
	setEncryptedValue := false

	if req.Value != nil {
		if req.SecretProviderId != nil || req.RemoteName != nil {
			return nil, status.Error(codes.InvalidArgument, "value is mutually exclusive with secret_provider_id and remote_name")
		}
		valueBytes, err := crypto.Encrypt(s.encryptionKey, []byte(req.GetValue()))
		if err != nil {
			return nil, status.Errorf(codes.Internal, "encrypt value: %v", err)
		}
		encryptedValue = &valueBytes
		setEncryptedValue = true
		setProviderID = true
		remoteValue := ""
		remoteName = &remoteValue
	} else if req.SecretProviderId != nil || req.RemoteName != nil {
		if req.SecretProviderId == nil || req.RemoteName == nil {
			return nil, status.Error(codes.InvalidArgument, "secret_provider_id and remote_name must be provided together")
		}
		parsed, err := parseUUID(req.GetSecretProviderId())
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "secret_provider_id: %v", err)
		}
		trimmedRemoteName := strings.TrimSpace(req.GetRemoteName())
		if trimmedRemoteName == "" {
			return nil, status.Error(codes.InvalidArgument, "remote_name must be provided")
		}
		providerID = &parsed
		setProviderID = true
		value := trimmedRemoteName
		remoteName = &value
		setEncryptedValue = true
		var cleared []byte
		encryptedValue = &cleared
	}

	secret, err := s.store.UpdateSecret(ctx, secretID, store.UpdateSecretInput{
		Title:               req.Title,
		Description:         req.Description,
		SecretProviderID:    providerID,
		SetSecretProviderID: setProviderID,
		RemoteName:          remoteName,
		EncryptedValue:      encryptedValue,
		SetEncryptedValue:   setEncryptedValue,
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
	if err := s.ensureSecretNotReferencedByEgressRules(ctx, secretID); err != nil {
		return nil, err
	}
	if err := s.store.DeleteSecret(ctx, secretID); err != nil {
		return nil, toStatusError(err)
	}
	return &secretsv1.DeleteSecretResponse{}, nil
}

func (s *Server) ensureSecretNotReferencedByEgressRules(ctx context.Context, secretID uuid.UUID) error {
	if s.egressRules == nil {
		return status.Error(codes.FailedPrecondition, "cannot verify egress rule references for secret deletion")
	}
	references, err := s.egressRules.CountRulesReferencingSecret(ctx, secretID.String())
	if err != nil {
		return status.Errorf(codes.FailedPrecondition, "cannot verify egress rule references for secret deletion: %v", err)
	}
	if references.Count == 0 {
		return nil
	}
	sort.Strings(references.EgressRuleIDs)
	return status.Errorf(
		codes.FailedPrecondition,
		"secret is referenced by %d egress rule(s): %s",
		references.Count,
		strings.Join(references.EgressRuleIDs, ", "),
	)
}

func (s *Server) ListSecrets(ctx context.Context, req *secretsv1.ListSecretsRequest) (*secretsv1.ListSecretsResponse, error) {
	organizationID, err := parseUUID(req.GetOrganizationId())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "organization_id: %v", err)
	}

	params := store.ListSecretsParams{
		OrganizationID: organizationID,
		PageSize:       req.GetPageSize(),
		PageToken:      req.GetPageToken(),
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
	if len(secret.EncryptedValue) > 0 {
		plaintext, err := crypto.Decrypt(s.encryptionKey, secret.EncryptedValue)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "decrypt secret: %v", err)
		}
		return &secretsv1.ResolveSecretResponse{Value: string(plaintext)}, nil
	}
	if secret.SecretProviderID == nil {
		return nil, status.Error(codes.FailedPrecondition, "secret has no provider")
	}
	value, err := s.resolveVaultValue(ctx, *secret.SecretProviderID, secret.RemoteName)
	if err != nil {
		return nil, mapVaultResolveError(err, "remote_name")
	}
	return &secretsv1.ResolveSecretResponse{Value: value}, nil
}

func (s *Server) ResolveSecretExists(ctx context.Context, req *secretsv1.ResolveSecretExistsRequest) (*secretsv1.ResolveSecretExistsResponse, error) {
	secretID, err := parseUUID(req.GetId())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "id: %v", err)
	}
	secret, err := s.store.GetSecret(ctx, secretID)
	if err != nil {
		if errors.Is(err, store.ErrSecretNotFound) {
			return &secretsv1.ResolveSecretExistsResponse{Exists: false}, nil
		}
		return nil, toStatusError(err)
	}
	return &secretsv1.ResolveSecretExistsResponse{
		Exists:         true,
		OrganizationId: secret.OrganizationID.String(),
	}, nil
}

func (s *Server) CreateImagePullSecret(ctx context.Context, req *secretsv1.CreateImagePullSecretRequest) (*secretsv1.CreateImagePullSecretResponse, error) {
	organizationID, err := parseUUID(req.GetOrganizationId())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "organization_id: %v", err)
	}

	registry := strings.TrimSpace(req.GetRegistry())
	if registry == "" {
		return nil, status.Error(codes.InvalidArgument, "registry must be provided")
	}
	username := strings.TrimSpace(req.GetUsername())
	if username == "" {
		return nil, status.Error(codes.InvalidArgument, "username must be provided")
	}

	var encryptedValue []byte
	var providerID *uuid.UUID
	valueReference := ""

	switch src := req.GetSource().(type) {
	case *secretsv1.CreateImagePullSecretRequest_Value:
		valueBytes, err := crypto.Encrypt(s.encryptionKey, []byte(src.Value))
		if err != nil {
			return nil, status.Errorf(codes.Internal, "encrypt value: %v", err)
		}
		encryptedValue = valueBytes
	case *secretsv1.CreateImagePullSecretRequest_Remote:
		ref, err := parseRemoteSecretRef(src.Remote)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "remote: %v", err)
		}
		providerID = &ref.ProviderID
		valueReference = ref.Reference
	default:
		return nil, status.Error(codes.InvalidArgument, "value or remote must be provided")
	}

	secret, err := s.store.CreateImagePullSecret(ctx, store.CreateImagePullSecretInput{
		OrganizationID:  organizationID,
		Description:     req.GetDescription(),
		Registry:        registry,
		Username:        username,
		EncryptedValue:  encryptedValue,
		ValueProviderID: providerID,
		ValueReference:  valueReference,
	})
	if err != nil {
		return nil, toStatusError(err)
	}

	return &secretsv1.CreateImagePullSecretResponse{ImagePullSecret: toProtoImagePullSecret(secret)}, nil
}

func (s *Server) GetImagePullSecret(ctx context.Context, req *secretsv1.GetImagePullSecretRequest) (*secretsv1.GetImagePullSecretResponse, error) {
	secretID, err := parseUUID(req.GetId())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "id: %v", err)
	}
	secret, err := s.store.GetImagePullSecret(ctx, secretID)
	if err != nil {
		return nil, toStatusError(err)
	}
	return &secretsv1.GetImagePullSecretResponse{ImagePullSecret: toProtoImagePullSecret(secret)}, nil
}

func (s *Server) UpdateImagePullSecret(ctx context.Context, req *secretsv1.UpdateImagePullSecretRequest) (*secretsv1.UpdateImagePullSecretResponse, error) {
	secretID, err := parseUUID(req.GetId())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "id: %v", err)
	}

	var registry *string
	if req.Registry != nil {
		trimmed := strings.TrimSpace(req.GetRegistry())
		if trimmed == "" {
			return nil, status.Error(codes.InvalidArgument, "registry must be provided")
		}
		registry = &trimmed
	}
	var username *string
	if req.Username != nil {
		trimmed := strings.TrimSpace(req.GetUsername())
		if trimmed == "" {
			return nil, status.Error(codes.InvalidArgument, "username must be provided")
		}
		username = &trimmed
	}

	var providerID *uuid.UUID
	var valueReference *string
	var encryptedValue *[]byte
	setProviderID := false
	setEncryptedValue := false

	switch src := req.GetSource().(type) {
	case *secretsv1.UpdateImagePullSecretRequest_Value:
		valueBytes, err := crypto.Encrypt(s.encryptionKey, []byte(src.Value))
		if err != nil {
			return nil, status.Errorf(codes.Internal, "encrypt value: %v", err)
		}
		encryptedValue = &valueBytes
		setEncryptedValue = true
		setProviderID = true
		clearedReference := ""
		valueReference = &clearedReference
	case *secretsv1.UpdateImagePullSecretRequest_Remote:
		ref, err := parseRemoteSecretRef(src.Remote)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "remote: %v", err)
		}
		providerID = &ref.ProviderID
		setProviderID = true
		valueReferenceValue := ref.Reference
		valueReference = &valueReferenceValue
		setEncryptedValue = true
		var cleared []byte
		encryptedValue = &cleared
	}

	secret, err := s.store.UpdateImagePullSecret(ctx, secretID, store.UpdateImagePullSecretInput{
		Description:        req.Description,
		Registry:           registry,
		Username:           username,
		ValueProviderID:    providerID,
		SetValueProviderID: setProviderID,
		ValueReference:     valueReference,
		EncryptedValue:     encryptedValue,
		SetEncryptedValue:  setEncryptedValue,
	})
	if err != nil {
		return nil, toStatusError(err)
	}
	return &secretsv1.UpdateImagePullSecretResponse{ImagePullSecret: toProtoImagePullSecret(secret)}, nil
}

func (s *Server) DeleteImagePullSecret(ctx context.Context, req *secretsv1.DeleteImagePullSecretRequest) (*secretsv1.DeleteImagePullSecretResponse, error) {
	secretID, err := parseUUID(req.GetId())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "id: %v", err)
	}
	if err := s.store.DeleteImagePullSecret(ctx, secretID); err != nil {
		return nil, toStatusError(err)
	}
	return &secretsv1.DeleteImagePullSecretResponse{}, nil
}

func (s *Server) ListImagePullSecrets(ctx context.Context, req *secretsv1.ListImagePullSecretsRequest) (*secretsv1.ListImagePullSecretsResponse, error) {
	organizationID, err := parseUUID(req.GetOrganizationId())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "organization_id: %v", err)
	}

	params := store.ListImagePullSecretsParams{
		OrganizationID: organizationID,
		PageSize:       req.GetPageSize(),
		PageToken:      req.GetPageToken(),
	}

	secrets, nextToken, err := s.store.ListImagePullSecrets(ctx, params)
	if err != nil {
		return nil, toStatusError(err)
	}

	resp := &secretsv1.ListImagePullSecretsResponse{
		ImagePullSecrets: make([]*secretsv1.ImagePullSecret, len(secrets)),
		NextPageToken:    nextToken,
	}
	for i, secret := range secrets {
		resp.ImagePullSecrets[i] = toProtoImagePullSecret(secret)
	}
	return resp, nil
}

func (s *Server) ResolveImagePullSecret(ctx context.Context, req *secretsv1.ResolveImagePullSecretRequest) (*secretsv1.ResolveImagePullSecretResponse, error) {
	secretID, err := parseUUID(req.GetId())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "id: %v", err)
	}
	secret, err := s.store.GetImagePullSecret(ctx, secretID)
	if err != nil {
		return nil, toStatusError(err)
	}
	if len(secret.EncryptedValue) > 0 {
		plaintext, err := crypto.Decrypt(s.encryptionKey, secret.EncryptedValue)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "decrypt secret: %v", err)
		}
		return &secretsv1.ResolveImagePullSecretResponse{
			Registry: secret.Registry,
			Username: secret.Username,
			Password: string(plaintext),
		}, nil
	}
	if secret.ValueProviderID == nil {
		return nil, status.Error(codes.FailedPrecondition, "image pull secret has no provider")
	}
	value, err := s.resolveVaultValue(ctx, *secret.ValueProviderID, secret.ValueReference)
	if err != nil {
		return nil, mapVaultResolveError(err, "value_reference")
	}
	return &secretsv1.ResolveImagePullSecretResponse{
		Registry: secret.Registry,
		Username: secret.Username,
		Password: value,
	}, nil
}

type vaultRemoteNameError struct {
	err error
}

func (e vaultRemoteNameError) Error() string {
	return e.err.Error()
}

func (e vaultRemoteNameError) Unwrap() error {
	return e.err
}

func (s *Server) resolveVaultValue(ctx context.Context, providerID uuid.UUID, remoteName string) (string, error) {
	provider, err := s.store.GetSecretProvider(ctx, providerID)
	if err != nil {
		return "", err
	}
	if provider.Type != store.ProviderTypeVault {
		return "", status.Errorf(codes.FailedPrecondition, "unsupported secret provider type: %s", provider.Type)
	}
	config, err := vaultConfigFromJSON(provider.Config)
	if err != nil {
		return "", status.Errorf(codes.Internal, "decode secret provider config: %v", err)
	}
	ref, err := parseVaultRemoteName(remoteName)
	if err != nil {
		return "", vaultRemoteNameError{err: err}
	}
	value, err := s.vault.ReadKV2(ctx, config.Address, config.Token, ref.Mount, ref.Path, ref.Key)
	if err != nil {
		return "", status.Errorf(codes.Internal, "resolve vault secret: %v", err)
	}
	return value, nil
}

func mapVaultResolveError(err error, field string) error {
	var remoteErr vaultRemoteNameError
	if errors.As(err, &remoteErr) {
		return status.Errorf(codes.InvalidArgument, "%s: %v", field, remoteErr.err)
	}
	if st, ok := status.FromError(err); ok {
		return st.Err()
	}
	return toStatusError(err)
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
	providerID := ""
	if secret.SecretProviderID != nil {
		providerID = secret.SecretProviderID.String()
	}
	return &secretsv1.Secret{
		Meta:             toProtoEntityMeta(secret.ID, secret.CreatedAt, secret.UpdatedAt),
		Title:            secret.Title,
		Description:      secret.Description,
		SecretProviderId: providerID,
		RemoteName:       secret.RemoteName,
	}
}

func toProtoImagePullSecret(secret store.ImagePullSecret) *secretsv1.ImagePullSecret {
	protoSecret := &secretsv1.ImagePullSecret{
		Meta:        toProtoEntityMeta(secret.ID, secret.CreatedAt, secret.UpdatedAt),
		Description: secret.Description,
		Registry:    secret.Registry,
		Username:    secret.Username,
	}
	if secret.ValueProviderID != nil {
		protoSecret.Source = &secretsv1.ImagePullSecret_Remote{
			Remote: &secretsv1.RemoteSecretRef{
				ValueProviderId: secret.ValueProviderID.String(),
				ValueReference:  secret.ValueReference,
			},
		}
	}
	return protoSecret
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

type remoteSecretRef struct {
	ProviderID uuid.UUID
	Reference  string
}

func parseRemoteSecretRef(ref *secretsv1.RemoteSecretRef) (remoteSecretRef, error) {
	if ref == nil {
		return remoteSecretRef{}, fmt.Errorf("reference must be provided")
	}
	providerID, err := parseUUID(ref.GetValueProviderId())
	if err != nil {
		return remoteSecretRef{}, fmt.Errorf("value_provider_id: %w", err)
	}
	reference := strings.TrimSpace(ref.GetValueReference())
	if reference == "" {
		return remoteSecretRef{}, fmt.Errorf("value_reference must be provided")
	}
	return remoteSecretRef{ProviderID: providerID, Reference: reference}, nil
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
	case errors.Is(err, store.ErrSecretProviderNotFound), errors.Is(err, store.ErrSecretNotFound), errors.Is(err, store.ErrImagePullSecretNotFound):
		return status.Error(codes.NotFound, err.Error())
	case errors.Is(err, store.ErrInvalidPageToken):
		return status.Error(codes.InvalidArgument, err.Error())
	default:
		return status.Errorf(codes.Internal, "internal error: %v", err)
	}
}
