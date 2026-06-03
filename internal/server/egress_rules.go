package server

import (
	"context"
	"fmt"
	"strings"

	egressv1 "github.com/agynio/secrets/gen/go/agynio/api/egress/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type EgressRulesClient interface {
	CountRulesReferencingSecret(ctx context.Context, secretID string) (EgressSecretReferences, error)
}

type EgressSecretReferences struct {
	Count         int32
	EgressRuleIDs []string
}

type egressRulesGRPCClient struct {
	client egressv1.EgressRulesServiceClient
}

func NewEgressRulesGRPCClient(conn grpc.ClientConnInterface) EgressRulesClient {
	return egressRulesGRPCClient{client: egressv1.NewEgressRulesServiceClient(conn)}
}

func DialEgressRulesClient(ctx context.Context, target string) (EgressRulesClient, *grpc.ClientConn, error) {
	trimmedTarget := strings.TrimSpace(target)
	if trimmedTarget == "" {
		return nil, nil, nil
	}
	conn, err := grpc.NewClient(trimmedTarget, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, nil, fmt.Errorf("create egress rules grpc client: %w", err)
	}
	return NewEgressRulesGRPCClient(conn), conn, nil
}

func (c egressRulesGRPCClient) CountRulesReferencingSecret(ctx context.Context, secretID string) (EgressSecretReferences, error) {
	resp, err := c.client.CountRulesReferencingSecret(ctx, &egressv1.CountRulesReferencingSecretRequest{SecretId: secretID})
	if err != nil {
		return EgressSecretReferences{}, err
	}
	return EgressSecretReferences{
		Count:         resp.GetCount(),
		EgressRuleIDs: resp.GetEgressRuleIds(),
	}, nil
}
