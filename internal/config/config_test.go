package config

import "testing"

// The reference-check targets default to each peer's name, so an install wires
// nothing. Left to the caller they arrive unset, and an unset target fails
// DeleteSecret closed.
func TestReferenceCheckTargetsDefault(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://x")
	t.Setenv("ENCRYPTION_KEY_FILE", "/etc/key")

	cfg, err := FromEnv()
	if err != nil {
		t.Fatalf("FromEnv: %v", err)
	}
	for _, test := range []struct{ name, got, want string }{
		{"egress rules", cfg.EgressRulesGRPCTarget, "egress:50051"},
		{"llm", cfg.LLMGRPCTarget, "llm:50051"},
		{"images", cfg.ImagesGRPCTarget, "images:50051"},
	} {
		if test.got != test.want {
			t.Errorf("%s target = %q, want %q", test.name, test.got, test.want)
		}
	}
}

func TestReferenceCheckTargetsOverride(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://x")
	t.Setenv("ENCRYPTION_KEY_FILE", "/etc/key")
	t.Setenv("IMAGES_GRPC_TARGET", "images.elsewhere:50051")

	cfg, err := FromEnv()
	if err != nil {
		t.Fatalf("FromEnv: %v", err)
	}
	if cfg.ImagesGRPCTarget != "images.elsewhere:50051" {
		t.Fatalf("images target = %q, want the override", cfg.ImagesGRPCTarget)
	}
}
