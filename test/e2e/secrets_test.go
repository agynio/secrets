//go:build e2e

package e2e

import (
	"context"
	"testing"
	"time"

	secretsv1 "github.com/agynio/secrets/gen/go/agynio/api/secrets/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

func TestGetSecretProviderRequiresID(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := grpc.NewClient(secretsAddress, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial secrets: %v", err)
	}
	defer conn.Close()

	client := secretsv1.NewSecretsServiceClient(conn)

	_, err = client.GetSecretProvider(ctx, &secretsv1.GetSecretProviderRequest{})
	if err == nil {
		t.Fatal("expected invalid argument error")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got %v", err)
	}
	if st.Code() != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument, got %s: %s", st.Code(), st.Message())
	}
}

func TestListSecretProvidersUsesOrganizationID(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := grpc.NewClient(secretsAddress, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial secrets: %v", err)
	}
	defer conn.Close()

	client := secretsv1.NewSecretsServiceClient(conn)

	_, err = client.ListSecretProviders(ctx, &secretsv1.ListSecretProvidersRequest{OrganizationId: testOrganizationID})
	if err != nil {
		t.Fatalf("list secret providers: %v", err)
	}
}
