package server

import (
	"context"
	"fmt"
	"strings"

	llmv1 "github.com/agynio/secrets/gen/go/agynio/api/llm/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// LLMClient answers whether any Subscription holds this secret by reference.
// Not a dependency cycle for the same reason the EgressRules one isn't: Secrets
// calls out only on delete, and the LLM service calls in only on subscription
// create and update.
type LLMClient interface {
	CountSubscriptionsReferencingSecret(ctx context.Context, secretID string) (SubscriptionSecretReferences, error)
}

type SubscriptionSecretReferences struct {
	Count           int32
	SubscriptionIDs []string
}

type llmGRPCClient struct {
	client llmv1.LLMServiceClient
}

func NewLLMGRPCClient(conn grpc.ClientConnInterface) LLMClient {
	return llmGRPCClient{client: llmv1.NewLLMServiceClient(conn)}
}

func DialLLMClient(ctx context.Context, target string) (LLMClient, *grpc.ClientConn, error) {
	trimmedTarget := strings.TrimSpace(target)
	if trimmedTarget == "" {
		return nil, nil, nil
	}
	conn, err := grpc.NewClient(trimmedTarget, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, nil, fmt.Errorf("create llm grpc client: %w", err)
	}
	return NewLLMGRPCClient(conn), conn, nil
}

func (c llmGRPCClient) CountSubscriptionsReferencingSecret(ctx context.Context, secretID string) (SubscriptionSecretReferences, error) {
	resp, err := c.client.CountSubscriptionsReferencingSecret(ctx, &llmv1.CountSubscriptionsReferencingSecretRequest{SecretId: secretID})
	if err != nil {
		return SubscriptionSecretReferences{}, err
	}
	return SubscriptionSecretReferences{
		Count:           resp.GetCount(),
		SubscriptionIDs: resp.GetSubscriptionIds(),
	}, nil
}
