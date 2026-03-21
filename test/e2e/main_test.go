//go:build e2e

package e2e

import (
	"os"
	"strings"
	"testing"
)

var secretsAddress = envOrDefault("SECRETS_ADDRESS", "secrets:50051")
var testOrganizationID = "11111111-1111-1111-1111-111111111111"

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
