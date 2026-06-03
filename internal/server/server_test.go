package server

import (
	"context"
	"errors"
	"strings"
	"testing"

	secretsv1 "github.com/agynio/secrets/gen/go/agynio/api/secrets/v1"
	"github.com/agynio/secrets/internal/store"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestParseVaultRemoteName(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    vaultRemoteRef
		wantErr bool
	}{
		{
			name:  "three segments",
			input: "kv/path/key",
			want: vaultRemoteRef{
				Mount: "kv",
				Path:  "path",
				Key:   "key",
			},
		},
		{
			name:  "multi segment path",
			input: "kv/path/to/secret",
			want: vaultRemoteRef{
				Mount: "kv",
				Path:  "path/to",
				Key:   "secret",
			},
		},
		{
			name:    "too few segments",
			input:   "kv/key",
			wantErr: true,
		},
		{
			name:    "empty segment",
			input:   "kv//key",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseVaultRemoteName(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("unexpected ref: %+v", got)
			}
		})
	}
}

func TestProviderTypeConversions(t *testing.T) {
	protoType, err := providerTypeToProto(store.ProviderTypeVault)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if protoType != secretsv1.SecretProviderType_SECRET_PROVIDER_TYPE_VAULT {
		t.Fatalf("unexpected proto type: %v", protoType)
	}

	storeType, err := providerTypeFromProto(protoType)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if storeType != store.ProviderTypeVault {
		t.Fatalf("unexpected store type: %v", storeType)
	}
}

func TestProviderTypeUnspecified(t *testing.T) {
	if _, err := providerTypeFromProto(secretsv1.SecretProviderType_SECRET_PROVIDER_TYPE_UNSPECIFIED); err == nil {
		t.Fatalf("expected error for unspecified provider type")
	}
	if _, err := providerTypeToProto(store.ProviderType("unknown")); err == nil {
		t.Fatalf("expected error for unknown provider type")
	}
}

func TestVaultConfigFromProtoValidation(t *testing.T) {
	tests := []struct {
		name   string
		config *secretsv1.SecretProviderConfig
	}{
		{
			name:   "nil config",
			config: nil,
		},
		{
			name: "missing address",
			config: &secretsv1.SecretProviderConfig{
				Provider: &secretsv1.SecretProviderConfig_Vault{
					Vault: &secretsv1.VaultConfig{Token: "token"},
				},
			},
		},
		{
			name: "missing token",
			config: &secretsv1.SecretProviderConfig{
				Provider: &secretsv1.SecretProviderConfig_Vault{
					Vault: &secretsv1.VaultConfig{Address: "https://vault"},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := vaultConfigFromProto(tt.config); err == nil {
				t.Fatalf("expected error")
			}
		})
	}
}

func TestToStatusError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		wantCode codes.Code
	}{
		{
			name:     "secret provider not found",
			err:      store.ErrSecretProviderNotFound,
			wantCode: codes.NotFound,
		},
		{
			name:     "secret not found",
			err:      store.ErrSecretNotFound,
			wantCode: codes.NotFound,
		},
		{
			name:     "image pull secret not found",
			err:      store.ErrImagePullSecretNotFound,
			wantCode: codes.NotFound,
		},
		{
			name:     "foreign key",
			err:      &pgconn.PgError{Code: "23503", Message: "fk"},
			wantCode: codes.FailedPrecondition,
		},
		{
			name:     "invalid page token",
			err:      store.ErrInvalidPageToken,
			wantCode: codes.InvalidArgument,
		},
		{
			name:     "generic error",
			err:      errors.New("boom"),
			wantCode: codes.Internal,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := toStatusError(tt.err)
			st, ok := status.FromError(err)
			if !ok {
				t.Fatalf("expected status error")
			}
			if st.Code() != tt.wantCode {
				t.Fatalf("expected code %v, got %v", tt.wantCode, st.Code())
			}
		})
	}
}

func TestNormalizePageSize(t *testing.T) {
	if got := store.NormalizePageSize(0); got != 50 {
		t.Fatalf("expected default page size, got %d", got)
	}
	if got := store.NormalizePageSize(-5); got != 50 {
		t.Fatalf("expected default page size for negative input, got %d", got)
	}
	if got := store.NormalizePageSize(1000); got != 100 {
		t.Fatalf("expected max page size, got %d", got)
	}
}

func TestPageTokenRoundTrip(t *testing.T) {
	encoded, err := store.EncodePageToken(42)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	decoded, err := store.DecodePageToken(encoded)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decoded != 42 {
		t.Fatalf("expected offset 42, got %d", decoded)
	}
}

func TestPageTokenInvalid(t *testing.T) {
	if _, err := store.DecodePageToken("invalid-token"); err == nil {
		t.Fatalf("expected error")
	} else if !errors.Is(err, store.ErrInvalidPageToken) {
		t.Fatalf("expected invalid page token error, got %v", err)
	}
}

func TestParseRemoteSecretRef(t *testing.T) {
	if _, err := parseRemoteSecretRef(nil); err == nil {
		t.Fatalf("expected error for nil ref")
	}
	if _, err := parseRemoteSecretRef(&secretsv1.RemoteSecretRef{ValueProviderId: "bad", ValueReference: "ref"}); err == nil {
		t.Fatalf("expected error for invalid provider id")
	}
	providerID := uuid.New()
	if _, err := parseRemoteSecretRef(&secretsv1.RemoteSecretRef{ValueProviderId: providerID.String(), ValueReference: " "}); err == nil {
		t.Fatalf("expected error for empty reference")
	}
	ref, err := parseRemoteSecretRef(&secretsv1.RemoteSecretRef{ValueProviderId: providerID.String(), ValueReference: "kv/path/key"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ref.ProviderID != providerID {
		t.Fatalf("unexpected provider id")
	}
	if ref.Reference != "kv/path/key" {
		t.Fatalf("unexpected reference")
	}
}

type fakeSecretStore struct {
	getSecret       store.Secret
	getSecretErr    error
	deletedSecretID uuid.UUID
}

func (f fakeSecretStore) CreateSecretProvider(context.Context, store.CreateSecretProviderInput) (store.SecretProvider, error) {
	panic("unexpected CreateSecretProvider")
}

func (f fakeSecretStore) GetSecretProvider(context.Context, uuid.UUID) (store.SecretProvider, error) {
	panic("unexpected GetSecretProvider")
}

func (f fakeSecretStore) UpdateSecretProvider(context.Context, uuid.UUID, store.UpdateSecretProviderInput) (store.SecretProvider, error) {
	panic("unexpected UpdateSecretProvider")
}

func (f fakeSecretStore) DeleteSecretProvider(context.Context, uuid.UUID) error {
	panic("unexpected DeleteSecretProvider")
}

func (f fakeSecretStore) ListSecretProviders(context.Context, store.ListSecretProvidersParams) ([]store.SecretProvider, string, error) {
	panic("unexpected ListSecretProviders")
}

func (f fakeSecretStore) CreateSecret(context.Context, store.CreateSecretInput) (store.Secret, error) {
	panic("unexpected CreateSecret")
}

func (f fakeSecretStore) GetSecret(context.Context, uuid.UUID) (store.Secret, error) {
	if f.getSecretErr != nil {
		return store.Secret{}, f.getSecretErr
	}
	return f.getSecret, nil
}

func (f fakeSecretStore) UpdateSecret(context.Context, uuid.UUID, store.UpdateSecretInput) (store.Secret, error) {
	panic("unexpected UpdateSecret")
}

func (f *fakeSecretStore) DeleteSecret(_ context.Context, id uuid.UUID) error {
	f.deletedSecretID = id
	return nil
}

func (f fakeSecretStore) ListSecrets(context.Context, store.ListSecretsParams) ([]store.Secret, string, error) {
	panic("unexpected ListSecrets")
}

func (f fakeSecretStore) CreateImagePullSecret(context.Context, store.CreateImagePullSecretInput) (store.ImagePullSecret, error) {
	panic("unexpected CreateImagePullSecret")
}

func (f fakeSecretStore) GetImagePullSecret(context.Context, uuid.UUID) (store.ImagePullSecret, error) {
	panic("unexpected GetImagePullSecret")
}

func (f fakeSecretStore) UpdateImagePullSecret(context.Context, uuid.UUID, store.UpdateImagePullSecretInput) (store.ImagePullSecret, error) {
	panic("unexpected UpdateImagePullSecret")
}

func (f fakeSecretStore) DeleteImagePullSecret(context.Context, uuid.UUID) error {
	panic("unexpected DeleteImagePullSecret")
}

func (f fakeSecretStore) ListImagePullSecrets(context.Context, store.ListImagePullSecretsParams) ([]store.ImagePullSecret, string, error) {
	panic("unexpected ListImagePullSecrets")
}

type fakeEgressRulesClient struct {
	references EgressSecretReferences
	err        error
	secretID   string
	called     bool
}

func (f *fakeEgressRulesClient) CountRulesReferencingSecret(_ context.Context, secretID string) (EgressSecretReferences, error) {
	f.called = true
	f.secretID = secretID
	if f.err != nil {
		return EgressSecretReferences{}, f.err
	}
	return f.references, nil
}

func TestResolveSecretExists(t *testing.T) {
	secretID := uuid.New()
	organizationID := uuid.New()
	secret := store.Secret{ID: secretID, OrganizationID: organizationID}

	resp, err := (&Server{store: &fakeSecretStore{getSecret: secret}}).ResolveSecretExists(context.Background(), &secretsv1.ResolveSecretExistsRequest{Id: secretID.String()})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.GetExists() {
		t.Fatalf("expected secret to exist")
	}
	if resp.GetOrganizationId() != organizationID.String() {
		t.Fatalf("expected organization_id %q, got %q", organizationID.String(), resp.GetOrganizationId())
	}

	resp, err = (&Server{store: &fakeSecretStore{getSecretErr: store.ErrSecretNotFound}}).ResolveSecretExists(context.Background(), &secretsv1.ResolveSecretExistsRequest{Id: secretID.String()})
	if err != nil {
		t.Fatalf("unexpected missing-secret error: %v", err)
	}
	if resp.GetExists() {
		t.Fatalf("expected missing secret response")
	}
	if resp.GetOrganizationId() != "" {
		t.Fatalf("expected empty organization_id, got %q", resp.GetOrganizationId())
	}
}

func TestDeleteSecretEgressReferenceCheck(t *testing.T) {
	secretID := uuid.New()

	t.Run("allows unreferenced delete", func(t *testing.T) {
		egressClient := &fakeEgressRulesClient{}
		store := &fakeSecretStore{}
		_, err := (&Server{store: store, egressRules: egressClient}).DeleteSecret(context.Background(), &secretsv1.DeleteSecretRequest{Id: secretID.String()})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !egressClient.called {
			t.Fatalf("expected egress reference check")
		}
		if egressClient.secretID != secretID.String() {
			t.Fatalf("expected checked secret id %q, got %q", secretID.String(), egressClient.secretID)
		}
		if store.deletedSecretID != secretID {
			t.Fatalf("expected deleted secret id %q, got %q", secretID, store.deletedSecretID)
		}
	})

	t.Run("rejects referenced delete", func(t *testing.T) {
		egressClient := &fakeEgressRulesClient{references: EgressSecretReferences{Count: 2, EgressRuleIDs: []string{"rule-b", "rule-a"}}}
		store := &fakeSecretStore{}
		_, err := (&Server{store: store, egressRules: egressClient}).DeleteSecret(context.Background(), &secretsv1.DeleteSecretRequest{Id: secretID.String()})
		assertStatusCode(t, err, codes.FailedPrecondition)
		if store.deletedSecretID != uuid.Nil {
			t.Fatalf("secret should not be deleted")
		}
		if !strings.Contains(err.Error(), "rule-a, rule-b") {
			t.Fatalf("expected referenced rule ids in error, got %v", err)
		}
	})

	t.Run("fails closed without client", func(t *testing.T) {
		store := &fakeSecretStore{}
		_, err := (&Server{store: store}).DeleteSecret(context.Background(), &secretsv1.DeleteSecretRequest{Id: secretID.String()})
		assertStatusCode(t, err, codes.FailedPrecondition)
		if store.deletedSecretID != uuid.Nil {
			t.Fatalf("secret should not be deleted")
		}
	})

	t.Run("fails closed on check error", func(t *testing.T) {
		egressClient := &fakeEgressRulesClient{err: errors.New("unavailable")}
		store := &fakeSecretStore{}
		_, err := (&Server{store: store, egressRules: egressClient}).DeleteSecret(context.Background(), &secretsv1.DeleteSecretRequest{Id: secretID.String()})
		assertStatusCode(t, err, codes.FailedPrecondition)
		if store.deletedSecretID != uuid.Nil {
			t.Fatalf("secret should not be deleted")
		}
	})
}

func assertStatusCode(t *testing.T, err error, want codes.Code) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error")
	}
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected status error, got %v", err)
	}
	if st.Code() != want {
		t.Fatalf("expected code %v, got %v", want, st.Code())
	}
}
