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
	cfg.EgressRulesGRPCTarget = os.Getenv("EGRESS_RULES_GRPC_TARGET")
	return cfg, nil
}
