package store

import (
	"errors"
	"testing"
)

func TestNormalizePageSize(t *testing.T) {
	tests := []struct {
		name string
		in   int32
		want int32
	}{
		{name: "default", in: 0, want: defaultPageSize},
		{name: "negative", in: -5, want: defaultPageSize},
		{name: "max", in: maxPageSize + 10, want: maxPageSize},
		{name: "custom", in: 10, want: 10},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := normalizePageSize(test.in)
			if got != test.want {
				t.Fatalf("expected %d, got %d", test.want, got)
			}
		})
	}
}

func TestPageTokenRoundTrip(t *testing.T) {
	token, err := encodePageToken(42)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got, err := decodePageToken(token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != 42 {
		t.Fatalf("expected 42, got %d", got)
	}
}

func TestDecodePageTokenInvalid(t *testing.T) {
	if _, err := decodePageToken(""); !errors.Is(err, ErrInvalidPageToken) {
		t.Fatalf("expected ErrInvalidPageToken for empty token")
	}
	if _, err := decodePageToken("not-base64"); !errors.Is(err, ErrInvalidPageToken) {
		t.Fatalf("expected ErrInvalidPageToken for invalid base64")
	}
	negativeToken, err := encodePageToken(-1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := decodePageToken(negativeToken); !errors.Is(err, ErrInvalidPageToken) {
		t.Fatalf("expected ErrInvalidPageToken for negative offset")
	}
}
