package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	secretsv1 "github.com/agynio/secrets/gen/go/agynio/api/secrets/v1"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc"

	"github.com/agynio/secrets/internal/config"
	"github.com/agynio/secrets/internal/crypto"
	"github.com/agynio/secrets/internal/db"
	"github.com/agynio/secrets/internal/server"
	"github.com/agynio/secrets/internal/store"
	"github.com/agynio/secrets/internal/vault"
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("secrets: %v", err)
	}
}

func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg, err := config.FromEnv()
	if err != nil {
		return err
	}

	encryptionKey, err := crypto.LoadKey(cfg.EncryptionKeyFile)
	if err != nil {
		return fmt.Errorf("load encryption key: %w", err)
	}

	poolCfg, err := pgxpool.ParseConfig(cfg.DatabaseURL)
	if err != nil {
		return fmt.Errorf("parse database url: %w", err)
	}
	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return fmt.Errorf("create connection pool: %w", err)
	}
	defer pool.Close()

	if err := db.ApplyMigrations(ctx, pool); err != nil {
		return fmt.Errorf("apply migrations: %w", err)
	}

	grpcServer := grpc.NewServer()
	secretsv1.RegisterSecretsServiceServer(grpcServer, server.New(store.NewStore(pool), vault.NewClient(http.DefaultClient), encryptionKey))

	lis, err := net.Listen("tcp", cfg.GRPCAddress)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", cfg.GRPCAddress, err)
	}

	go func() {
		<-ctx.Done()
		grpcServer.GracefulStop()
	}()

	log.Printf("SecretsService listening on %s", cfg.GRPCAddress)

	if err := grpcServer.Serve(lis); err != nil {
		if errors.Is(err, grpc.ErrServerStopped) {
			return nil
		}
		return fmt.Errorf("serve: %w", err)
	}
	return nil
}
