package server

import (
	"context"
	"fmt"
	"strings"

	imagesv1 "github.com/agynio/secrets/gen/go/agynio/api/images/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// ImagesClient answers whether any Image holds this secret by reference as its
// registry credential. Not a dependency cycle, for the same reason the LLM one
// isn't: Secrets calls out only on delete, and the Images service calls in only
// on image create and update.
type ImagesClient interface {
	CountImagesReferencingSecret(ctx context.Context, secretID string) (ImageSecretReferences, error)
}

type ImageSecretReferences struct {
	Count    int32
	ImageIDs []string
}

type imagesGRPCClient struct {
	client imagesv1.ImagesServiceClient
}

func NewImagesGRPCClient(conn grpc.ClientConnInterface) ImagesClient {
	return imagesGRPCClient{client: imagesv1.NewImagesServiceClient(conn)}
}

func DialImagesClient(ctx context.Context, target string) (ImagesClient, *grpc.ClientConn, error) {
	trimmedTarget := strings.TrimSpace(target)
	if trimmedTarget == "" {
		return nil, nil, nil
	}
	conn, err := grpc.NewClient(trimmedTarget, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, nil, fmt.Errorf("create images grpc client: %w", err)
	}
	return NewImagesGRPCClient(conn), conn, nil
}

func (c imagesGRPCClient) CountImagesReferencingSecret(ctx context.Context, secretID string) (ImageSecretReferences, error) {
	resp, err := c.client.CountImagesReferencingSecret(ctx, &imagesv1.CountImagesReferencingSecretRequest{SecretId: secretID})
	if err != nil {
		return ImageSecretReferences{}, err
	}
	return ImageSecretReferences{
		Count:    resp.GetCount(),
		ImageIDs: resp.GetImageIds(),
	}, nil
}
