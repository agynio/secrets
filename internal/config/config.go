package config

import (
	"fmt"
	"os"
)

type Config struct {
	GRPCAddress           string
	DatabaseURL           string
	EncryptionKeyFile     string
	EgressRulesGRPCTarget string
	LLMGRPCTarget         string
	ImagesGRPCTarget      string
}

func FromEnv() (Config, error) {
	cfg := Config{}
	cfg.GRPCAddress = os.Getenv("GRPC_ADDRESS")
	if cfg.GRPCAddress == "" {
		cfg.GRPCAddress = ":50051"
	}
	cfg.DatabaseURL = os.Getenv("DATABASE_URL")
	if cfg.DatabaseURL == "" {
		return Config{}, fmt.Errorf("DATABASE_URL must be set")
	}
	cfg.EncryptionKeyFile = os.Getenv("ENCRYPTION_KEY_FILE")
	if cfg.EncryptionKeyFile == "" {
		return Config{}, fmt.Errorf("ENCRYPTION_KEY_FILE must be set")
	}
	// Every service this one asks about a secret reference is a peer in the same
	// namespace, reachable at its own name. Defaulting means an install wires
	// nothing: an operator sets these only to point somewhere else. Left to the
	// caller they arrive unset, and an unset target fails DeleteSecret closed.
	cfg.EgressRulesGRPCTarget = envOr("EGRESS_RULES_GRPC_TARGET", "egress:50051")
	cfg.LLMGRPCTarget = envOr("LLM_GRPC_TARGET", "llm:50051")
	cfg.ImagesGRPCTarget = envOr("IMAGES_GRPC_TARGET", "images:50051")
	return cfg, nil
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
