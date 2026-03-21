package calleridentity

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"google.golang.org/grpc/metadata"
)

func TestFromContextSuccess(t *testing.T) {
	tenantID := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(
		metadataTenantID, tenantID.String(),
		metadataIdentityID, "identity-123",
		metadataIdentityType, "user",
		metadataAuthMethod, "token",
	))

	caller, err := FromContext(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if caller.TenantID != tenantID {
		t.Fatalf("expected tenant id %s, got %s", tenantID, caller.TenantID)
	}
	if caller.IdentityID != "identity-123" {
		t.Fatalf("expected identity id, got %q", caller.IdentityID)
	}
	if caller.IdentityType != "user" {
		t.Fatalf("expected identity type, got %q", caller.IdentityType)
	}
	if caller.AuthMethod != "token" {
		t.Fatalf("expected auth method, got %q", caller.AuthMethod)
	}
}

func TestFromContextMissingTenantID(t *testing.T) {
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(
		metadataIdentityID, "identity-123",
	))
	if _, err := FromContext(ctx); err == nil {
		t.Fatalf("expected error")
	}
}

func TestFromContextInvalidTenantID(t *testing.T) {
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(
		metadataTenantID, "not-a-uuid",
	))
	if _, err := FromContext(ctx); err == nil {
		t.Fatalf("expected error")
	}
}

func TestFromContextMissingMetadata(t *testing.T) {
	if _, err := FromContext(context.Background()); err == nil {
		t.Fatalf("expected error")
	}
}
