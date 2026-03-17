package server

import (
	"errors"
	"testing"

	secretsv1 "github.com/agynio/secrets/.gen/go/agynio/api/secrets/v1"
	"github.com/agynio/secrets/internal/store"
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
