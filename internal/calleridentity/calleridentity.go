package calleridentity

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"google.golang.org/grpc/metadata"
)

const (
	metadataTenantID     = "x-agyn-tenant-id"
	metadataIdentityID   = "x-agyn-identity-id"
	metadataIdentityType = "x-agyn-identity-type"
	metadataAuthMethod   = "x-agyn-auth-method"
)

type CallerIdentity struct {
	TenantID     uuid.UUID
	IdentityID   string
	IdentityType string
	AuthMethod   string
}

func FromContext(ctx context.Context) (CallerIdentity, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return CallerIdentity{}, fmt.Errorf("missing grpc metadata")
	}
	tenantValue := strings.TrimSpace(firstValue(md.Get(metadataTenantID)))
	if tenantValue == "" {
		return CallerIdentity{}, fmt.Errorf("x-agyn-tenant-id metadata key missing")
	}
	tenantID, err := uuid.Parse(tenantValue)
	if err != nil {
		return CallerIdentity{}, fmt.Errorf("invalid tenant id: %w", err)
	}

	return CallerIdentity{
		TenantID:     tenantID,
		IdentityID:   strings.TrimSpace(firstValue(md.Get(metadataIdentityID))),
		IdentityType: strings.TrimSpace(firstValue(md.Get(metadataIdentityType))),
		AuthMethod:   strings.TrimSpace(firstValue(md.Get(metadataAuthMethod))),
	}, nil
}

func firstValue(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}
