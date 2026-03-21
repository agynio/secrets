package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

type Client struct {
	httpClient *http.Client
}

func NewClient(httpClient *http.Client) *Client {
	return &Client{httpClient: httpClient}
}

func (c *Client) ReadKV2(ctx context.Context, address, token, mount, path, key string) (string, error) {
	base := strings.TrimRight(address, "/")
	url := fmt.Sprintf("%s/v1/%s/data/%s", base, mount, path)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}
	request.Header.Set("X-Vault-Token", token)

	response, err := c.httpClient.Do(request)
	if err != nil {
		return "", fmt.Errorf("vault request: %w", err)
	}
	defer func() {
		_ = response.Body.Close()
	}()

	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(response.Body)
		message := strings.TrimSpace(string(body))
		if message == "" {
			message = response.Status
		}
		return "", fmt.Errorf("vault response status %d: %s", response.StatusCode, message)
	}

	var payload struct {
		Data struct {
			Data map[string]any `json:"data"`
		} `json:"data"`
	}
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		return "", fmt.Errorf("decode vault response: %w", err)
	}
	value, ok := payload.Data.Data[key]
	if !ok {
		return "", fmt.Errorf("vault secret missing key %q", key)
	}
	text, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("vault secret key %q is not a string", key)
	}
	return text, nil
}
