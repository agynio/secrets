package server

import (
	"errors"
	"testing"

	secretsv1 "github.com/agynio/secrets/gen/go/agynio/api/secrets/v1"
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
			name:  "simple",
			input: "kv/app/password",
			want:  vaultRemoteRef{Mount: "kv", Path: "app", Key: "password"},
		},
		{
			name:  "multi-level",
			input: "kv/team/app/password",
			want:  vaultRemoteRef{Mount: "kv", Path: "team/app", Key: "password"},
		},
		{
			name:    "too few segments",
			input:   "kv/password",
			wantErr: true,
		},
		{
			name:    "empty segment",
			input:   "kv//password",
			wantErr: true,
		},
		{
			name:    "trailing slash",
			input:   "kv/app/",
			wantErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := parseVaultRemoteName(test.input)
			if test.wantErr {
				if err == nil {
					t.Fatalf("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != test.want {
				t.Fatalf("expected %+v, got %+v", test.want, got)
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

	if _, err := providerTypeFromProto(secretsv1.SecretProviderType_SECRET_PROVIDER_TYPE_UNSPECIFIED); err == nil {
		t.Fatalf("expected error for unspecified provider type")
	}
	if _, err := providerTypeToProto(store.ProviderType("unknown")); err == nil {
		t.Fatalf("expected error for unknown provider type")
	}
}

func TestVaultConfigFromProtoValidation(t *testing.T) {
	if _, err := vaultConfigFromProto(nil); err == nil {
		t.Fatalf("expected error for nil config")
	}

	missingAddress := &secretsv1.SecretProviderConfig{
		Config: &secretsv1.SecretProviderConfig_Vault{
			Vault: &secretsv1.VaultConfig{Token: "token"},
		},
	}
	if _, err := vaultConfigFromProto(missingAddress); err == nil {
		t.Fatalf("expected error for missing address")
	}

	missingToken := &secretsv1.SecretProviderConfig{
		Config: &secretsv1.SecretProviderConfig_Vault{
			Vault: &secretsv1.VaultConfig{Address: "https://vault"},
		},
	}
	if _, err := vaultConfigFromProto(missingToken); err == nil {
		t.Fatalf("expected error for missing token")
	}

	valid := &secretsv1.SecretProviderConfig{
		Config: &secretsv1.SecretProviderConfig_Vault{
			Vault: &secretsv1.VaultConfig{Address: "https://vault", Token: "token"},
		},
	}
	if _, err := vaultConfigFromProto(valid); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestToStatusError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		code codes.Code
	}{
		{
			name: "pg fk violation",
			err:  &pgconn.PgError{Code: "23503", Message: "fk violation"},
			code: codes.FailedPrecondition,
		},
		{
			name: "provider not found",
			err:  store.ErrSecretProviderNotFound,
			code: codes.NotFound,
		},
		{
			name: "secret not found",
			err:  store.ErrSecretNotFound,
			code: codes.NotFound,
		},
		{
			name: "invalid page token",
			err:  store.ErrInvalidPageToken,
			code: codes.InvalidArgument,
		},
		{
			name: "internal error",
			err:  errors.New("boom"),
			code: codes.Internal,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			statusErr := toStatusError(test.err)
			st := status.Convert(statusErr)
			if st.Code() != test.code {
				t.Fatalf("expected code %v, got %v", test.code, st.Code())
			}
		})
	}
}
