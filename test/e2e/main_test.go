//go:build e2e

package e2e

import (
	"context"
	"os"
	"strings"
	"testing"

	"google.golang.org/grpc/metadata"
)

var secretsAddress = envOrDefault("SECRETS_ADDRESS", "secrets:50051")
var testTenantID = "11111111-1111-1111-1111-111111111111"

func envOrDefault(key, fallback string) string {
	value, ok := os.LookupEnv(key)
	if !ok {
		return fallback
	}
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return fallback
	}
	return trimmed
}

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}

func contextWithTenant(ctx context.Context) context.Context {
	return metadata.NewOutgoingContext(ctx, metadata.Pairs(
		"x-agyn-tenant-id", testTenantID,
		"x-agyn-identity-id", "identity-123",
		"x-agyn-identity-type", "user",
		"x-agyn-auth-method", "token",
	))
}
